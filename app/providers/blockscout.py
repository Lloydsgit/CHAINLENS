"""Blockscout v2 API client for deep EVM address intelligence.

Blockscout exposes verified contract metadata, exact transaction and token
transfer counters, ERC-20 balances with logos, and NFT holdings — all keyless.
It complements the raw JSON-RPC client, which is still used for authoritative
balance/nonce reads.
"""
from __future__ import annotations

from typing import Any, Optional

from . import http

# Blockscout hosts per-chain instances under predictable hostnames. Only the
# ones that answered without a bot challenge are listed.
BASES = {
    "ETH": "https://eth.blockscout.com",
    "OPTIMISM": "https://optimism.blockscout.com",
    "ZKSYNC": "https://zksync.blockscout.com",
    "SCROLL": "https://scroll.blockscout.com",
    "GNOSIS": "https://gnosis.blockscout.com",
}


def _wei(value: Any, decimals: int = 18) -> Optional[float]:
    try:
        return int(value) / (10 ** decimals)
    except (TypeError, ValueError):
        return None


async def address_info(address: str, chain: str = "ETH") -> dict:
    """Core address record: balance, type, creator, implementation."""
    base = BASES.get(chain)
    if not base:
        return {}
    try:
        data = await http.fetch_json(f"{base}/api/v2/addresses/{address}", ttl=120)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        "source": "Blockscout",
        "balance": _wei(data.get("coin_balance")),
        "is_contract": data.get("is_contract"),
        "contract_name": (data.get("name") or "").strip() or None,
        "creator": data.get("creator_address_hash"),
        "creation_tx": data.get("creation_tx_hash"),
        "creation_status": data.get("creation_status"),
        "implementation": (data.get("implementations") or [{}])[0].get("address_hash")
        if data.get("implementations")
        else None,
        "is_verified": data.get("is_verified"),
        "proxy_type": data.get("proxy_type"),
        "has_tokens": data.get("has_tokens"),
        "has_logs": data.get("has_logs"),
        "has_nft": data.get("has_nft"),
        "token_holder_count": data.get("token_holder_count"),
        "watchlist_names": data.get("watchlist_names"),
        "public_tags": [t.get("display_name") for t in data.get("public_tags") or []],
        "tags": [t.get("display_name") for t in data.get("metadata", {}).get("tags", [])]
        if isinstance(data.get("metadata"), dict)
        else [],
        "reputation": data.get("reputation"),
    }


async def counters(address: str, chain: str = "ETH") -> dict:
    """Exact lifetime counters for the address."""
    base = BASES.get(chain)
    if not base:
        return {}
    try:
        data = await http.fetch_json(f"{base}/api/v2/addresses/{address}/counters", ttl=120)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}

    def as_int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    return {
        "transactions": as_int(data.get("transactions_count")),
        "token_transfers": as_int(data.get("token_transfers_count")),
        "gas_usage": as_int(data.get("gas_usage_count")),
        "validations": as_int(data.get("validations_count")),
    }


async def token_balances(address: str, chain: str = "ETH") -> list[dict]:
    """ERC-20 balances with symbol, decimals, logo and USD price where known."""
    base = BASES.get(chain)
    if not base:
        return []
    try:
        data = await http.fetch_json(
            f"{base}/api/v2/addresses/{address}/token-balances",
            ttl=180,
            timeout=12,
            retries=0,
        )
    except Exception:
        return []
    # This endpoint returns a bare list; older deployments wrap it in "items".
    items = data if isinstance(data, list) else (data or {}).get("items", [])
    out = []
    for item in items:
        token = item.get("token") or {}
        decimals = token.get("decimals") or "18"
        try:
            dec = int(decimals)
        except (TypeError, ValueError):
            dec = 18
        amount = _wei(item.get("value"), dec)
        rate = token.get("exchange_rate")
        try:
            price = float(rate) if rate is not None else None
        except (TypeError, ValueError):
            price = None
        out.append(
            {
                "symbol": token.get("symbol"),
                "name": token.get("name"),
                "contract": token.get("address_hash") or token.get("address"),
                "decimals": dec,
                "amount": amount,
                "price_usd": price,
                "value_usd": (amount * price) if (amount is not None and price) else None,
                "type": token.get("type"),
                "holders": token.get("holders_count"),
                "icon": token.get("icon_url"),
            }
        )
    return out


async def nfts(address: str, chain: str = "ETH", limit: int = 24) -> dict:
    """NFT collections held, with counts per collection."""
    base = BASES.get(chain)
    if not base:
        return {"count": 0, "collections": []}
    try:
        data = await http.fetch_json(f"{base}/api/v2/addresses/{address}/nft", ttl=180)
    except Exception:
        return {"count": 0, "collections": []}
    items = (data or {}).get("items", []) or []
    collections: dict[str, dict] = {}
    for item in items:
        token = item.get("token") or {}
        key = token.get("address_hash") or token.get("address") or token.get("name") or "?"
        entry = collections.setdefault(
            key,
            {
                "name": token.get("name"),
                "symbol": token.get("symbol"),
                "type": token.get("type"),
                "contract": key,
                "count": 0,
                "icon": token.get("icon_url"),
            },
        )
        entry["count"] += int(item.get("value") or 1) if str(item.get("value") or "1").isdigit() else 1
    ordered = sorted(collections.values(), key=lambda c: c["count"], reverse=True)
    return {"count": len(collections), "collections": ordered[:limit]}


async def token_info(token: str, chain: str = "ETH") -> dict:
    """Token metadata (name, symbol, type) for a contract address."""
    base = BASES.get(chain)
    if not base:
        return {}
    try:
        data = await http.fetch_json(f"{base}/api/v2/tokens/{token}", ttl=86400)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        "name": data.get("name"),
        "symbol": data.get("symbol"),
        "type": data.get("type"),
    }


async def transactions(address: str, chain: str = "ETH", limit: int = 30) -> list[dict]:
    """Recent normal transactions with method, value and counterparty."""
    base = BASES.get(chain)
    if not base:
        return []
    try:
        data = await http.fetch_json(
            f"{base}/api/v2/addresses/{address}/transactions", ttl=90
        )
    except Exception:
        return []
    out = []
    for tx in (data or {}).get("items", [])[:limit]:
        frm = (tx.get("from") or {}).get("hash")
        to = (tx.get("to") or {}).get("hash")
        method = tx.get("method")
        if isinstance(method, dict):
            method = method.get("method_id")
        out.append(
            {
                "hash": tx.get("hash"),
                "timestamp": tx.get("timestamp"),
                "from": frm,
                "to": to,
                "value": _wei(tx.get("value")),
                "method": method,
                "raw_input": tx.get("raw_input"),
                "status": tx.get("status"),
                "block": tx.get("block_number"),
                "fee": _wei(tx.get("fee", {}).get("value")) if isinstance(tx.get("fee"), dict) else None,
                "gas_used": tx.get("gas_used"),
            }
        )
    return out


async def token_transfers(address: str, chain: str = "ETH", limit: int = 40) -> list[dict]:
    """Recent ERC-20/721 transfers in and out, with counterparty and token.

    Blockscout attaches its label set (entity names, categories, verified
    domains, scam flags) to the ``from``/``to`` objects here, which is the
    richest keyless source of counterparty attribution.
    """
    base = BASES.get(chain)
    if not base:
        return []
    try:
        data = await http.fetch_json(
            f"{base}/api/v2/addresses/{address}/token-transfers", ttl=120, timeout=12, retries=0
        )
    except Exception:
        return []
    out = []
    for ev in (data or {}).get("items", [])[:limit]:
        token = ev.get("token") or {}
        total = ev.get("total") or {}
        try:
            dec = int(total.get("decimals") or token.get("decimals") or 18)
        except (TypeError, ValueError):
            dec = 18
        try:
            amount = int(total.get("value") or 0) / (10 ** dec)
        except (TypeError, ValueError):
            amount = None
        out.append(
            {
                "hash": ev.get("transaction_hash"),
                "timestamp": ev.get("timestamp"),
                "from": (ev.get("from") or {}).get("hash") if isinstance(ev.get("from"), dict) else ev.get("from"),
                "to": (ev.get("to") or {}).get("hash") if isinstance(ev.get("to"), dict) else ev.get("to"),
                "from_party": ev.get("from") if isinstance(ev.get("from"), dict) else None,
                "to_party": ev.get("to") if isinstance(ev.get("to"), dict) else None,
                "token": {"symbol": token.get("symbol"), "name": token.get("name"), "address": token.get("address_hash") or token.get("address")},
                "amount": amount,
                "type": ev.get("type"),
                "token_type": ev.get("token_type"),
            }
        )
    return out


async def contract_info(address: str, chain: str = "ETH") -> dict:
    """Verified source metadata for a contract address."""
    base = BASES.get(chain)
    if not base:
        return {}
    try:
        data = await http.fetch_json(f"{base}/api/v2/smart-contracts/{address}", ttl=3600)
    except Exception:
        return {}
    if not isinstance(data, dict) or not data:
        return {}
    return {
        "verified": data.get("is_verified"),
        "name": data.get("name"),
        "compiler": data.get("compiler_version"),
        "language": data.get("language"),
        "optimization": data.get("optimization_enabled"),
        "license": data.get("license_type"),
        "proxy_type": data.get("proxy_type"),
        "implementations": [i.get("address") for i in data.get("implementations") or []],
        "constructor_args": data.get("constructor_args"),
        "verified_at": data.get("verified_at"),
    }
