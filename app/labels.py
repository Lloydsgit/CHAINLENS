"""Curated address labels for well-known public contracts and venues.

These are community-sourced and deliberately conservative: only widely
documented addresses are included. They are advisory context, not attribution.

``jurisdiction`` records where a *service* is registered or regulated. It is a
property of the service, never of the person who used it. Only venue addresses
that have been confirmed against a live explorer are included.
"""
from __future__ import annotations

ETH_LABELS = {
    "0x0000000000000000000000000000000000000000": ("Null address", "burn"),
    "0x000000000000000000000000000000000000dead": ("Burn address", "burn"),
    "0x00000000219ab540356cbb839cbe05303d7705fa": (
        "Eth2 Beacon Deposit Contract",
        "infrastructure",
    ),
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": ("Wrapped Ether (WETH)", "token"),
    "0xdac17f958d2ee523a2206206994597c13d831ec7": ("Tether USD (USDT)", "token"),
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ("USD Coin (USDC)", "token"),
    "0x6b175474e89094c44da98b954eedeac495271d0f": ("Dai Stablecoin (DAI)", "token"),
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": ("Wrapped BTC (WBTC)", "token"),
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": (
        "Uniswap V2 Router",
        "infrastructure",
    ),
    "0xe592427a0aece92de3edee1f18e0157c05861564": (
        "Uniswap V3 SwapRouter",
        "infrastructure",
    ),
    "0x1111111254eeb25477b68fb85ed929f73a960582": (
        "1inch Aggregation Router V5",
        "infrastructure",
    ),
    # --- Mixers (verified against Blockscout contract names) ---
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": (
        "Tornado Cash: Proxy",
        "mixer",
        "Sanctioned by US OFAC (Aug 2022); developers charged in Netherlands",
    ),
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": (
        "Tornado Cash: Router",
        "mixer",
        "Sanctioned by US OFAC (Aug 2022); developers charged in Netherlands",
    ),
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": (
        "Tornado Cash: 10 ETH pool",
        "mixer",
        "Sanctioned by US OFAC (Aug 2022); developers charged in Netherlands",
    ),
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": (
        "Tornado Cash: 100 ETH pool",
        "mixer",
        "Sanctioned by US OFAC (Aug 2022); developers charged in Netherlands",
    ),
    "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc": (
        "Tornado Cash: 0.1 ETH pool",
        "mixer",
        "Sanctioned by US OFAC (Aug 2022); developers charged in Netherlands",
    ),
}


def label_eth(address: str):
    entry = ETH_LABELS.get(address.lower())
    if not entry:
        return None
    out = {"name": entry[0], "category": entry[1], "source": "curated labels"}
    if len(entry) > 2:
        out["jurisdiction"] = entry[2]
    return out
