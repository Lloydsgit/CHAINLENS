"""Solana provider (public mainnet JSON-RPC)."""
from __future__ import annotations

from typing import Any

from . import http

RPC = "https://api.mainnet-beta.solana.com"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
LAMPORTS = 10**9


async def _rpc(method: str, params: list) -> Any:
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    data = await http.fetch_json(RPC, method="POST", json_body=body, ttl=30)
    if isinstance(data, dict) and "result" in data:
        return data["result"]
    raise RuntimeError(str(data.get("error") if isinstance(data, dict) else data))


async def get_account(address: str) -> dict:
    out: dict[str, Any] = {"address": address, "chain": "SOL"}
    try:
        res = await _rpc("getBalance", [address])
        lamports = res.get("value", 0) if isinstance(res, dict) else 0
        out["balance_lamports"] = lamports
        out["balance_native"] = lamports / LAMPORTS
    except Exception as exc:
        out["error"] = str(exc)
    try:
        info = await _rpc("getAccountInfo", [address, {"encoding": "base64"}])
        out["exists"] = bool(info and info.get("value"))
        if info and info.get("value"):
            out["is_executable"] = info["value"].get("executable")
            out["owner_program"] = info["value"].get("owner")
    except Exception:
        pass
    return out


async def get_tokens(address: str) -> list:
    try:
        res = await _rpc(
            "getTokenAccountsByOwner",
            [address, {"programId": TOKEN_PROGRAM}, {"encoding": "jsonParsed"}],
        )
    except Exception:
        return []
    accounts = (res or {}).get("value") or []
    tokens = []
    for acct in accounts:
        info = (
            acct.get("account", {}).get("data", {}).get("parsed", {}).get("info", {})
        )
        amount = info.get("tokenAmount", {})
        tokens.append(
            {
                "mint": info.get("mint"),
                "amount": amount.get("uiAmount"),
                "decimals": amount.get("decimals"),
                "raw": amount.get("amount"),
            }
        )
    return tokens


async def get_signatures(address: str, limit: int = 25) -> list:
    try:
        return await _rpc("getSignaturesForAddress", [address, {"limit": limit}])
    except Exception:
        return []
