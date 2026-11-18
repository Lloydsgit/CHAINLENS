"""ENS / reverse-resolution provider (keyless public APIs).

`api.ensdata.net` supports forward and reverse resolution plus text records
(avatar, description, socials, content hash) with no key.
"""
from __future__ import annotations

from . import http

BASE = "https://api.ensdata.net"


async def forward(name: str) -> dict:
    """Resolve an ENS name to its address and public profile records."""
    try:
        data = await http.fetch_json(f"{BASE}/{name}", ttl=300)
    except Exception as exc:
        return {"name": name, "resolved": False, "error": str(exc)}
    if not isinstance(data, dict) or not data.get("address"):
        return {"name": name, "resolved": False}
    return {
        "name": name,
        "resolved": True,
        "address": data.get("address"),
        "avatar": data.get("avatar"),
        "description": data.get("description"),
        "content_hash": data.get("contentHash"),
        "url": data.get("url"),
        "website": data.get("url"),
        "twitter": data.get("twitter"),
        "github": data.get("github"),
        "email": data.get("email"),
        "discord": data.get("discord"),
        "telegram": data.get("telegram"),
        "pgp": data.get("pgp"),
        "header": data.get("header"),
        "wallets": data.get("wallets"),
        "records": data,
    }


async def reverse(address: str) -> dict:
    """Reverse-resolve an address to its primary ENS name and profile."""
    try:
        data = await http.fetch_json(f"{BASE}/{address}", ttl=300)
    except Exception as exc:
        return {"resolved": False, "error": str(exc)}
    if not isinstance(data, dict) or not data.get("name"):
        return {"resolved": False}
    return {
        "resolved": True,
        "name": data.get("name"),
        "avatar": data.get("avatar"),
        "description": data.get("description"),
        "url": data.get("url"),
        "twitter": data.get("twitter"),
        "github": data.get("github"),
        "email": data.get("email"),
        "discord": data.get("discord"),
        "telegram": data.get("telegram"),
        "records": data,
    }
