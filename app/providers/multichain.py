"""Cross-chain presence sweep for one EVM address.

Most explorers show you one chain at a time. An investigator needs the opposite
question answered first: *where does this address actually exist, and where is
the value?* The same 0x address is valid on every EVM chain, so a wallet can be
empty on Ethereum and hold real money on Base.

Each chain is queried through its Blockscout v2 instance (keyless). Balances are
authoritative reads from the explorer's own index; the native price is applied
by the caller so all chains share one price table.
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional

from . import http

# Blockscout instances per chain. Values were confirmed to answer the v2 API
# without a bot challenge. Native symbol/decimals are needed to price the gas
# token, which differs per chain.
CHAINS: dict[str, dict[str, Any]] = {
    "ETH": {"base": "https://eth.blockscout.com", "symbol": "ETH", "decimals": 18, "name": "Ethereum"},
    "BASE": {"base": "https://base.blockscout.com", "symbol": "ETH", "decimals": 18, "name": "Base"},
    "ARBITRUM": {"base": "https://arbitrum.blockscout.com", "symbol": "ETH", "decimals": 18, "name": "Arbitrum One"},
    "OPTIMISM": {"base": "https://explorer.optimism.io", "symbol": "ETH", "decimals": 18, "name": "OP Mainnet"},
    "POLYGON": {"base": "https://polygon.blockscout.com", "symbol": "POL", "decimals": 18, "name": "Polygon PoS"},
    "GNOSIS": {"base": "https://gnosisscan.io", "symbol": "xDAI", "decimals": 18, "name": "Gnosis Chain"},
    "ZKSYNC": {"base": "https://zksync.blockscout.com", "symbol": "ETH", "decimals": 18, "name": "zkSync Era"},
    "SCROLL": {"base": "https://scroll.blockscout.com", "symbol": "ETH", "decimals": 18, "name": "Scroll"},
}


def _to_float(value: Any, decimals: int) -> Optional[float]:
    try:
        return int(value) / (10 ** decimals)
    except (TypeError, ValueError):
        return None


async def _chain_presence(address: str, chain: str, meta: dict) -> dict:
    """Native balance, contract flag and name for one chain."""
    base = meta["base"]
    try:
        data = await http.fetch_json(f"{base}/api/v2/addresses/{address}", ttl=180, timeout=12, retries=0)
    except Exception as exc:  # noqa: BLE001 - a chain being down is not fatal
        return {"chain": chain, "name": meta["name"], "error": str(exc)[:120]}
    if not isinstance(data, dict) or not data:
        return {"chain": chain, "name": meta["name"], "error": "no data"}

    balance = _to_float(data.get("coin_balance"), meta["decimals"])
    return {
        "chain": chain,
        "name": meta["name"],
        "symbol": meta["symbol"],
        "balance": balance,
        "is_contract": data.get("is_contract"),
        "contract_name": (data.get("name") or "").strip() or None,
        "tx_count": data.get("transactions_count"),
        "has_tokens": data.get("has_tokens"),
        "has_nft": data.get("has_nft"),
    }


async def _chain_tokens(address: str, chain: str, meta: dict, limit: int) -> dict:
    """Token balances for one chain, ranked by the explorer's own valuation."""
    base = meta["base"]
    try:
        data = await http.fetch_json(
            f"{base}/api/v2/addresses/{address}/token-balances",
            ttl=180,
            timeout=14,
            retries=0,
        )
    except Exception:
        return {"chain": chain, "tokens": []}
    items = data if isinstance(data, list) else (data or {}).get("items", []) or []
    out = []
    for item in items:
        token = item.get("token") or {}
        try:
            dec = int(token.get("decimals") or 18)
        except (TypeError, ValueError):
            dec = 18
        amount = _to_float(item.get("value"), dec)
        rate = token.get("exchange_rate")
        try:
            price = float(rate) if rate is not None else None
        except (TypeError, ValueError):
            price = None
        out.append(
            {
                "chain": chain,
                "symbol": token.get("symbol"),
                "name": token.get("name"),
                "contract": token.get("address_hash") or token.get("address"),
                "amount": amount,
                "price_usd": price,
                "value_usd": (amount * price) if (amount is not None and price) else None,
                "holders": token.get("holders_count"),
            }
        )
    out.sort(key=lambda t: (t.get("value_usd") or 0), reverse=True)
    return {"chain": chain, "tokens": out[:limit]}


async def sweep(address: str, *, native_prices: Optional[dict] = None, token_limit: int = 12) -> dict:
    """Query every supported chain concurrently and consolidate the result.

    ``native_prices`` maps a symbol to its USD price so the gas-token balance on
    each chain can be valued; tokens carry their own explorer price.
    """
    addr = address.lower()
    prices = {k.upper(): v for k, v in (native_prices or {}).items() if v}

    presence, tokens = await asyncio.gather(
        asyncio.gather(*(_chain_presence(addr, c, m) for c, m in CHAINS.items())),
        asyncio.gather(*(_chain_tokens(addr, c, m, token_limit) for c, m in CHAINS.items())),
    )
    tokens_by_chain = {t["chain"]: t["tokens"] for t in tokens}

    chains_out = []
    for entry in presence:
        chain = entry["chain"]
        symbol = entry.get("symbol")
        price = prices.get(symbol.upper()) if symbol else None
        balance = entry.get("balance")
        native_usd = (balance * price) if (balance is not None and price) else None

        chain_tokens = tokens_by_chain.get(chain, [])
        token_usd = sum(t["value_usd"] or 0 for t in chain_tokens)

        entry = {
            **entry,
            "native_price_usd": price,
            "native_value_usd": native_usd,
            "tokens": chain_tokens,
            "token_count": len(chain_tokens),
            "token_value_usd": token_usd or None,
            "chain_value_usd": (native_usd or 0) + token_usd if (native_usd or token_usd) else None,
        }
        chains_out.append(entry)

    active = [c for c in chains_out if not c.get("error")]
    with_funds = [c for c in active if (c.get("chain_value_usd") or 0) > 0]
    with_activity = [c for c in active if (c.get("tx_count") or 0) > 0]
    total = sum(c.get("chain_value_usd") or 0 for c in chains_out) or None

    return {
        "address": addr,
        "chains_checked": len(CHAINS),
        "chains_active": len(active),
        "chains_with_funds": len(with_funds),
        "chains_with_activity": len(with_activity),
        "total_value_usd": total,
        "chains": sorted(
            chains_out,
            key=lambda c: (c.get("chain_value_usd") or 0, c.get("tx_count") or 0),
            reverse=True,
        ),
        "errors": [f"{c['chain']}: {c['error']}" for c in chains_out if c.get("error")],
    }
