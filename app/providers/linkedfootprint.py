"""Linked-footprint intelligence for a wallet.

A blockchain address itself has no IP and no location -- it is a cryptographic
key, not a network endpoint. But a wallet can *publish* a website (for example
through an ENS ``url`` record), and that website is a real network endpoint with
a real hosting IP and a real geolocation. This module follows that legitimate
on-chain -> off-chain link: resolve the published URL, extract its public
metadata, resolve its hostname to an IP, and hand that IP to the geolocation
providers.

Everything here is a property of the linked *website*, never of the wallet.
"""
from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

from . import geo, http

_TAG_RE = {
    "title": re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S),
    "description": re.compile(
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', re.I | re.S
    ),
    "og_title": re.compile(
        r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\'](.*?)["\']', re.I | re.S
    ),
    "og_description": re.compile(
        r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\'](.*?)["\']', re.I | re.S
    ),
    "og_image": re.compile(
        r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\'](.*?)["\']', re.I | re.S
    ),
    "generator": re.compile(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']', re.I | re.S
    ),
    "theme_color": re.compile(
        r'<meta[^>]+name=["\']theme-color["\'][^>]+content=["\'](.*?)["\']', re.I | re.S
    ),
    "favicon": re.compile(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]+href=["\'](.*?)["\']', re.I),
}

# Lightweight, high-signal fingerprints. This is a best-effort guess, not a
# full Wappalyzer.
_TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes"],
    "Ghost": [r"ghost-", r'content="Ghost'],
    "Hugo": [r"hugo", r"generator\" content=\"Hugo"],
    "Next.js": [r"/_next/static"],
    "Nuxt": [r"/_nuxt/"],
    "React": [r"react-dom", r"data-reactroot"],
    "Vue.js": [r"vue(\.min)?\.js", r"data-v-"],
    "Svelte": [r"svelte-"],
    "Google Analytics": [r"googletagmanager\.com", r"google-analytics\.com"],
    "Cloudflare": [r"cdnjs\.cloudflare\.com", r"cloudflare"],
    "jsDelivr": [r"cdn\.jsdelivr\.net"],
    "unpkg": [r"unpkg\.com"],
    "Bootstrap": [r"bootstrap(\.min)?\.(css|js)"],
    "Tailwind CSS": [r"tailwind"],
    "jQuery": [r"jquery"],
    "Font Awesome": [r"font-awesome", r"fontawesome"],
    "Google Fonts": [r"fonts\.googleapis\.com", r"fonts\.gstatic\.com"],
    "Stripe": [r"js\.stripe\.com"],
    "Matomo": [r"matomo\.js", r"piwik"],
    "Plausible": [r"plausible\.io"],
}


def _clean(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    text = re.sub(r"\s+", " ", text).strip()
    return text[:400] or None


def _normalize_url(url: str) -> Optional[str]:
    if not url:
        return None
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _detect_tech(html: str) -> list[str]:
    found = []
    for name, patterns in _TECH_SIGNATURES.items():
        if any(re.search(p, html, re.I) for p in patterns):
            found.append(name)
    return found


def _extract(html: str, base_url: str) -> dict:
    out: dict = {}
    for key, rx in _TAG_RE.items():
        m = rx.search(html)
        if m:
            out[key] = _clean(m.group(1))
    # Resolve the favicon to an absolute URL when it is relative.
    if out.get("favicon") and out["favicon"].startswith("//"):
        out["favicon"] = urlparse(base_url).scheme + ":" + out["favicon"]
    elif out.get("favicon") and out["favicon"].startswith("/"):
        p = urlparse(base_url)
        out["favicon"] = f"{p.scheme}://{p.netloc}{out['favicon']}"
    out["technologies"] = _detect_tech(html)
    return out


async def investigate(website_url: str, ens_name: Optional[str] = None) -> Optional[dict]:
    """Follow a published website to its hosting IP and geolocation.

    Returns ``None`` when there is no usable website. The returned dict always
    labels the result as a property of the *website*, not the wallet.
    """
    url = _normalize_url(website_url or "")
    if not url:
        return None
    host = urlparse(url).hostname
    if not host:
        return None

    out: dict = {
        "url": url,
        "host": host,
        "source": f"ENS {ens_name} url record" if ens_name else "wallet-published website",
        "scope": "Linked website (off-chain) -- not the wallet address itself",
    }

    html = None
    try:
        html = await http.fetch_text(url, ttl=1800)
    except Exception as exc:  # noqa: BLE001 - site may block or be down
        out["fetch_error"] = str(exc)
    if html:
        out.update(_extract(html, url))
        out["reachable"] = True
        try:
            out["bytes"] = len(html)
        except TypeError:
            pass
    else:
        out["reachable"] = False

    # Resolve the hostname and geolocate its hosting IP.
    resolved = await geo.resolve_host(host)
    out["addresses"] = resolved.get("addresses", [])
    if resolved.get("primary_ip"):
        out["ip"] = resolved["primary_ip"]
        out["geo"] = resolved.get("geo") or {}
    elif resolved.get("error"):
        out["resolve_error"] = resolved["error"]
    return out
