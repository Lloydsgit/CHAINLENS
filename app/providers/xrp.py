"""XRP Ledger provider (public XRPL cluster)."""
from __future__ import annotations

from typing import Any

from . import http

RPC = "https://xrplcluster.com/"
DROPS = 10**6


async def _rpc(method: str, params: list) -> Any:
    body = {"method": method, "params": params}
    data = await http.fetch_json(RPC, method="POST", json_body=body, ttl=30)
    result = data.get("result", {}) if isinstance(data, dict) else {}
    if result.get("status") == "error" or "error" in result:
        raise RuntimeError(result.get("error_message") or result.get("error"))
    return result


async def get_account(address: str) -> dict:
    out: dict[str, Any] = {"address": address, "chain": "XRP"}
    try:
        info = await _rpc("account_info", [{"account": address, "ledger_index": "validated"}])
        account_data = info.get("account_data", {})
        balance = int(account_data.get("Balance", 0))
        out.update(
            {
                "exists": True,
                "balance_drops": balance,
                "balance_native": balance / DROPS,
                "owner_count": account_data.get("OwnerCount"),
                "sequence": account_data.get("Sequence"),
                "flags": account_data.get("Flags"),
                "previous_txn_id": account_data.get("PreviousTxnID"),
            }
        )
    except Exception as exc:
        out["exists"] = False
        out["error"] = str(exc)
    return out


async def get_trustlines(address: str) -> list:
    try:
        res = await _rpc(
            "account_lines", [{"account": address, "ledger_index": "validated"}]
        )
    except Exception:
        return []
    return res.get("lines", []) or []


async def get_transactions(address: str, limit: int = 25) -> list:
    try:
        res = await _rpc(
            "account_tx",
            [{"account": address, "ledger_index_min": -1, "ledger_index_max": -1, "limit": limit}],
        )
    except Exception:
        return []
    return res.get("transactions", []) or []
