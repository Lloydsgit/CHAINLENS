"""Dogecoin provider (Dogechain.info public API)."""
from __future__ import annotations

from . import http

BASE = "https://dogechain.info/api/v1"


async def get_balance(address: str) -> dict:
    data = await http.fetch_json(f"{BASE}/address/balance/{address}", ttl=90)
    balance = float(data.get("balance", 0) or 0)
    confirmed = float(data.get("confirmed", 0) or 0)
    unconfirmed = float(data.get("unconfirmed", 0) or 0)
    return {
        "address": address,
        "chain": "DOGE",
        "balance_native": balance,
        "confirmed_native": confirmed,
        "unconfirmed_native": unconfirmed,
    }


async def get_transactions(address: str, limit: int = 25) -> list:
    try:
        data = await http.fetch_json(f"{BASE}/address/transactions/{address}", ttl=60)
    except Exception:
        return []
    txs = data.get("transactions") or []
    return txs[:limit]
