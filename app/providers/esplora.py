"""Esplora-compatible provider for Bitcoin and Litecoin (Blockstream stack)."""
from __future__ import annotations

from typing import Any

from .. import config
from . import http


def _base(chain: str) -> str:
    return config.EXPLORERS[chain]


async def get_address(chain: str, address: str) -> dict:
    data = await http.fetch_json(f"{_base(chain)}/address/{address}", ttl=90)
    chain_stats = data.get("chain_stats", {})
    mempool_stats = data.get("mempool_stats", {})
    confirmed = chain_stats.get("funded_txo_sum", 0) - chain_stats.get("spent_txo_sum", 0)
    unconfirmed = mempool_stats.get("funded_txo_sum", 0) - mempool_stats.get("spent_txo_sum", 0)
    return {
        "address": address,
        "chain": chain,
        "balance_sats": confirmed,
        "balance_native": confirmed / 1e8,
        "unconfirmed_sats": unconfirmed,
        "unconfirmed_native": unconfirmed / 1e8,
        "tx_count": chain_stats.get("tx_count", 0),
        "funded_txo_count": chain_stats.get("funded_txo_count", 0),
        "spent_txo_count": chain_stats.get("spent_txo_count", 0),
        "received_sats": chain_stats.get("funded_txo_sum", 0),
        "sent_sats": chain_stats.get("spent_txo_sum", 0),
        "mempool_tx_count": mempool_stats.get("tx_count", 0),
    }


async def get_transactions(chain: str, address: str, limit: int = 25) -> list:
    try:
        txs = await http.fetch_json(f"{_base(chain)}/address/{address}/txs", ttl=60)
    except Exception:
        return []
    return txs[:limit] if isinstance(txs, list) else []


async def get_utxos(chain: str, address: str) -> list:
    try:
        return await http.fetch_json(f"{_base(chain)}/address/{address}/utxo", ttl=60)
    except Exception:
        return []


async def tip_height(chain: str) -> Any:
    try:
        return await http.fetch_json(f"{_base(chain)}/blocks/tip/height", ttl=30)
    except Exception:
        return None
