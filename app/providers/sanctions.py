"""Sanctions screening against public OFAC SDN crypto-address lists.

The lists are published by 0xB10C from the US Treasury OFAC SDN dataset and are
refreshed daily. Addresses are cached on disk so screening is fast and offline
after the first fetch.
"""
from __future__ import annotations

import os
import time
from typing import Optional

from .. import config
from . import http

_CACHE: dict[str, dict[str, str]] = {}


def _local_path(chain: str) -> str:
    return os.path.join(config.CACHE_DIR, "ofac", f"{chain}.txt")


def _load_local(chain: str) -> Optional[set]:
    path = _local_path(chain)
    if not os.path.exists(path):
        return None
    if time.time() - os.path.getmtime(path) > config.OFAC_TTL:
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return {line.strip() for line in fh if line.strip() and not line.startswith("#")}
    except Exception:
        return None


def _store_local(chain: str, text: str) -> set:
    """Parse a sanctions list, caching it to disk when that is possible.

    The disk cache is an optimization only. On a read-only filesystem the
    parsed list is still returned so screening works; it simply is not
    persisted for the next run.
    """
    entries = {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")}
    try:
        os.makedirs(os.path.dirname(_local_path(chain)), exist_ok=True)
        with open(_local_path(chain), "w", encoding="utf-8") as fh:
            fh.write(text)
    except Exception:
        pass
    return entries


async def _get_list(chain: str) -> set:
    if chain in _CACHE:
        return _CACHE[chain]
    local = _load_local(chain)
    if local is not None:
        _CACHE[chain] = {a.lower(): a for a in local}
        return _CACHE[chain]
    filename = config.OFAC_LISTS.get(chain)
    if not filename:
        _CACHE[chain] = {}
        return _CACHE[chain]
    try:
        text = await http.fetch_text(f"{config.OFAC_BASE}/{filename}", ttl=config.OFAC_TTL)
        stored = _store_local(chain, text)
        _CACHE[chain] = {a.lower(): a for a in stored}
    except Exception:
        _CACHE[chain] = {}
    return _CACHE[chain]


async def screen(chain: str, address: str) -> dict:
    """Return sanctions match status for an address on a given chain."""
    if chain not in config.OFAC_LISTS:
        return {"checked": False, "listed": False, "reason": "no OFAC list for chain"}
    listing = await _get_list(chain)
    if not listing:
        return {"checked": False, "listed": False, "reason": "OFAC list unavailable"}
    key = address.lower()
    listed = key in listing
    return {
        "checked": True,
        "listed": listed,
        "source": "OFAC SDN (via 0xB10C public mirror)",
        "matched_address": listing.get(key) if listed else None,
    }


async def address_set(chain: str) -> set:
    """The full lowercased OFAC address set for a chain.

    Fund-flow taint screening needs to test many counterparties at once, which a
    single-address ``screen`` call cannot do. Returns an empty set when the list
    is unavailable, so callers degrade to "not screened" rather than crashing.
    """
    if chain not in config.OFAC_LISTS:
        return set()
    return set(await _get_list(chain))
