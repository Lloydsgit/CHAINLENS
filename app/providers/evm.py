"""Ethereum / EVM provider.

Uses a pool of public JSON-RPC endpoints for on-chain reads and the Ethplorer
public API for token holdings, prices and transfer history. Both have working
keyless tiers; keys only raise rate limits.
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional

from .. import config
from . import http

WEI = 10**18


async def _rpc(method: str, params: list) -> Any:
    """Try each configured RPC endpoint until one answers.

    Retries are disabled here and the timeout is short on purpose: we already
    iterate several endpoints, so a slow or rejecting node should be abandoned
    quickly for the next one. Letting ``fetch_json`` retry each URL would stack
    timeouts across the whole list and stall the report.
    """
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    last_err: Optional[Exception] = None
    for url in config.ETH_RPC_URLS:
        try:
            data = await http.fetch_json(
                url, method="POST", json_body=body, ttl=30, retries=0, timeout=8.0
            )
            if isinstance(data, dict) and "result" in data:
                return data["result"]
            if isinstance(data, dict) and "error" in data:
                last_err = RuntimeError(str(data["error"]))
                continue
        except Exception as exc:  # noqa: BLE001
            last_err = exc
    if last_err:
        raise last_err
    raise RuntimeError("no EVM RPC endpoint available")


async def get_core(address: str) -> dict:
    """Balance, nonce, code size and contract/token flags."""
    addr = address.lower()
    result: dict[str, Any] = {"address": addr, "chain": "ETH"}

    async def safe(coro, default=None):
        try:
            return await coro
        except Exception:
            return default

    balance_hex, nonce_hex, code = await asyncio.gather(
        safe(_rpc("eth_getBalance", [addr, "latest"])),
        safe(_rpc("eth_getTransactionCount", [addr, "latest"])),
        safe(_rpc("eth_getCode", [addr, "latest"])),
    )

    if balance_hex:
        result["balance_wei"] = int(balance_hex, 16)
        result["balance_native"] = int(balance_hex, 16) / WEI
    if nonce_hex:
        result["nonce"] = int(nonce_hex, 16)
        result["outgoing_tx_count"] = int(nonce_hex, 16)
    if isinstance(code, str):
        hexcode = code[2:] if code.startswith("0x") else code
        # EIP-7702 delegation designator: 0xef0100 || 20-byte delegate address.
        # Such an account is still an EOA that delegates execution to a contract.
        if hexcode.startswith("ef0100") and len(hexcode) == 2 * 23:
            result["is_contract"] = False
            result["is_delegated_eoa"] = True
            result["delegate_address"] = "0x" + hexcode[6:].lower()
        else:
            result["is_contract"] = len(hexcode) > 0
            result["bytecode_size"] = len(hexcode) // 2
    return result


async def ethplorer_address(address: str) -> dict:
    addr = address.lower()
    return await http.fetch_json(
        f"https://api.ethplorer.io/getAddressInfo/{addr}",
        params={"apiKey": config.ETHPLORER_API_KEY},
        ttl=120,
    )


async def block_number() -> int:
    """Current head block number."""
    return int(await _rpc("eth_blockNumber", []), 16)


async def eth_call(to: str, data: str, *, block: str = "latest") -> Optional[str]:
    """Raw eth_call returning the hex result, or None on failure."""
    try:
        return await _rpc("eth_call", [{"to": to, "data": data}, block])
    except Exception:
        return None


async def get_logs(*, address: str, topics: list, from_block: int, to_block: int) -> list:
    """eth_getLogs against a single address. Returns [] when unsupported."""
    try:
        params = {
            "address": address,
            "topics": topics,
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block),
        }
        result = await _rpc("eth_getLogs", [params])
        return result if isinstance(result, list) else []
    except Exception:
        return []


async def ethplorer_transactions(address: str, limit: int = 40) -> list:
    addr = address.lower()
    try:
        return await http.fetch_json(
            f"https://api.ethplorer.io/getAddressTransactions/{addr}",
            params={"apiKey": config.ETHPLORER_API_KEY, "limit": limit},
            ttl=120,
        )
    except Exception:
        return []


async def ethplorer_history(address: str, limit: int = 60) -> list:
    addr = address.lower()
    try:
        data = await http.fetch_json(
            f"https://api.ethplorer.io/getAddressHistory/{addr}",
            params={"apiKey": config.ETHPLORER_API_KEY, "limit": limit},
            ttl=120,
        )
    except Exception:
        return []
    if isinstance(data, dict):
        return data.get("operations") or []
    return data if isinstance(data, list) else []


async def get_identity(address: str) -> dict:
    """Best-effort contract name / token metadata via Ethplorer."""
    info = await ethplorer_address(address)
    out: dict[str, Any] = {}
    contract = info.get("contractInfo") or {}
    if contract:
        out["contract_name"] = contract.get("name")
        out["contract_symbol"] = contract.get("symbol")
        out["token_decimals"] = contract.get("decimals")
        out["token_total_supply"] = contract.get("totalSupply")
    out["raw"] = info
    return out
