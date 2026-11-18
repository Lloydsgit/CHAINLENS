"""Tron provider (TronGrid public API)."""
from __future__ import annotations

from .. import config
from . import http

BASE = "https://api.trongrid.io"
SUN = 10**6


def _headers() -> dict:
    headers = {}
    if config.TRONGRID_API_KEY:
        headers["TRON-PRO-API-KEY"] = config.TRONGRID_API_KEY
    return headers


async def get_account(address: str) -> dict:
    try:
        data = await http.fetch_json(
            f"{BASE}/v1/accounts/{address}", headers=_headers(), ttl=90
        )
    except Exception:
        # An unknown or malformed address makes TronGrid return 400; the report
        # must still render, so treat it as a not-found account.
        return {"address": address, "chain": "TRON", "exists": False, "balance_native": 0.0}
    accounts = data.get("data") or []
    if not accounts:
        return {"address": address, "chain": "TRON", "exists": False, "balance_native": 0.0}
    acct = accounts[0]
    balance_sun = acct.get("balance", 0) or 0
    frozen = (
        (acct.get("frozen_balance", 0) or 0)
        + (acct.get("account_resource", {}) or {}).get("frozen_balance_for_energy", 0)
    )
    created_ms = acct.get("create_time")
    return {
        "address": address,
        "chain": "TRON",
        "exists": True,
        "balance_sun": balance_sun,
        "balance_native": balance_sun / SUN,
        "frozen_native": frozen / SUN,
        "created_at": created_ms,
        "is_contract": bool(acct.get("is_contract")),
        "permissions": acct.get("owner_permission"),
    }


async def get_transactions(address: str, limit: int = 30) -> list:
    try:
        data = await http.fetch_json(
            f"{BASE}/v1/accounts/{address}/transactions",
            params={"limit": limit},
            headers=_headers(),
            ttl=60,
        )
    except Exception:
        return []
    return data.get("data") or []


async def get_trc20_transfers(address: str, limit: int = 30) -> list:
    try:
        data = await http.fetch_json(
            f"{BASE}/v1/accounts/{address}/transactions/trc20",
            params={"limit": limit},
            headers=_headers(),
            ttl=60,
        )
    except Exception:
        return []
    return data.get("data") or []
