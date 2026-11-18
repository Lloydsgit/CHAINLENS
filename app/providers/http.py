"""Shared async HTTP client with TTL caching, per-host throttling and polite retries."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from .. import config

_client: Optional[httpx.AsyncClient] = None
_lock = asyncio.Lock()

# Many public data providers (notably Blockscout) throttle by *concurrency*:
# firing a dozen parallel requests at one host returns 429 even though the
# request rate is low. A small per-host gate keeps the fan-out from tripping
# that limit, which matters because the analyzer gathers providers in parallel.
_HOST_LIMIT = int(os.getenv("OSINT_HOST_CONCURRENCY", "3"))
# Minimum spacing between requests to the same host. Free provider tiers
# (Blockscout especially) rate-limit by requests-per-second, so concurrency
# alone is not enough: the requests must also be spread out in time.
_HOST_INTERVAL = float(os.getenv("OSINT_HOST_INTERVAL", "0.34"))
_host_gates: dict[str, asyncio.Semaphore] = {}
_host_next: dict[str, float] = {}
_host_gates_lock = asyncio.Lock()


async def _host_gate(url: str) -> asyncio.Semaphore:
    host = urlparse(url).netloc
    gate = _host_gates.get(host)
    if gate is None:
        async with _host_gates_lock:
            gate = _host_gates.setdefault(host, asyncio.Semaphore(_HOST_LIMIT))
    return gate


async def _throttle(url: str) -> None:
    """Space requests to one host so a burst does not trip a per-second quota."""
    if _HOST_INTERVAL <= 0:
        return
    host = urlparse(url).netloc
    async with _host_gates_lock:
        now = time.monotonic()
        wait = max(0.0, _host_next.get(host, 0.0) - now)
        _host_next[host] = max(now, _host_next.get(host, 0.0)) + _HOST_INTERVAL
    if wait > 0:
        await asyncio.sleep(wait)


async def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        async with _lock:
            if _client is None:
                _client = httpx.AsyncClient(
                    timeout=config.HTTP_TIMEOUT,
                    headers={"User-Agent": config.USER_AGENT, "Accept": "application/json"},
                    follow_redirects=True,
                    limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
                )
    return _client


async def close_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


def _cache_path(key: str) -> str:
    digest = hashlib.sha256(key.encode()).hexdigest()[:32]
    return os.path.join(config.CACHE_DIR, f"{digest}.json")


def _is_error_envelope(data: Any) -> bool:
    """Detect provider-level error bodies that must never be cached as data."""
    if not isinstance(data, dict):
        return False
    if data.get("status") == "0" and "result" in data:
        msg = str(data.get("message") or "").lower()
        if data.get("result") in (None, "", []) and any(
            k in msg for k in ("rate", "too many", "limit", "quota", "invalid api", "notok")
        ):
            return True
    err = data.get("error")
    if isinstance(err, dict):
        msg = str(err.get("message") or "").lower()
        if any(k in msg for k in ("rate limit", "too many", "exceeded", "quota")):
            return True
    return False


def _error_message(data: dict) -> str:
    if isinstance(data.get("error"), dict):
        return str(data["error"].get("message") or "provider error")
    return str(data.get("message") or "provider error")


def _cache_read(key: str) -> Any:
    path = _cache_path(key)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            blob = json.load(fh)
        if time.time() - blob.get("t", 0) > blob.get("ttl", config.CACHE_TTL):
            return None
        return blob.get("v")
    except Exception:
        return None


def _cache_write(key: str, value: Any, ttl: int) -> None:
    os.makedirs(config.CACHE_DIR, exist_ok=True)
    try:
        with open(_cache_path(key), "w", encoding="utf-8") as fh:
            json.dump({"t": time.time(), "ttl": ttl, "v": value}, fh)
    except Exception:
        pass


async def fetch_json(
    url: str,
    *,
    method: str = "GET",
    params: Optional[dict] = None,
    json_body: Optional[dict] = None,
    headers: Optional[dict] = None,
    ttl: Optional[int] = None,
    retries: Optional[int] = None,
    timeout: Optional[float] = None,
) -> Any:
    """Fetch JSON with a small disk cache and retry on transient failures.

    ``timeout`` overrides the client default for endpoints known to be slow
    (for example Blockscout's aggregated token list).
    """
    ttl = config.CACHE_TTL if ttl is None else ttl
    retries = config.HTTP_RETRIES if retries is None else retries
    cache_key = json.dumps([method, url, params, json_body, headers], sort_keys=True, default=str)
    if ttl > 0:
        cached = _cache_read(cache_key)
        if cached is not None:
            return cached

    client = await get_client()
    gate = await _host_gate(url)
    # httpx treats an explicit ``timeout=None`` as "no timeout at all" rather
    # than "use the client default", so only pass it when an override is given.
    req_kwargs: dict[str, Any] = {}
    if timeout is not None:
        req_kwargs["timeout"] = timeout
    last_err: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            async with gate:
                await _throttle(url)
                resp = await client.request(
                    method, url, params=params, json=json_body, headers=headers, **req_kwargs
                )
            if resp.status_code == 429 and attempt < retries:
                await asyncio.sleep(2.0 * (attempt + 1))
                continue
            resp.raise_for_status()
            data = resp.json()
            # Provider error envelopes (rate limits, quota) are not data: never
            # cache them, or a transient throttle poisons the cache for its TTL.
            if _is_error_envelope(data):
                last_err = RuntimeError(_error_message(data))
                if attempt < retries:
                    await asyncio.sleep(1.2 * (attempt + 1))
                    continue
                raise last_err
            if ttl > 0:
                _cache_write(cache_key, data, ttl)
            return data
        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            # A timeout or refused connection means the endpoint is slow or
            # unreachable. Retrying just multiplies the wait (retries x timeout),
            # which is exactly what stalls a report when a public provider
            # accepts the connection and then never answers. Fail fast instead.
            raise exc
        except Exception as exc:  # noqa: BLE001 - provider errors are non-fatal
            last_err = exc
            if attempt < retries:
                await asyncio.sleep(0.6 * (attempt + 1))
    raise last_err if last_err else RuntimeError("request failed")


async def fetch_text(url: str, *, ttl: Optional[int] = None) -> str:
    ttl = config.CACHE_TTL if ttl is None else ttl
    cache_key = f"text::{url}"
    if ttl > 0:
        cached = _cache_read(cache_key)
        if cached is not None:
            return cached
    client = await get_client()
    resp = await client.get(url)
    resp.raise_for_status()
    text = resp.text
    if ttl > 0:
        _cache_write(cache_key, text, ttl)
    return text
