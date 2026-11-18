"""Price provider (CoinGecko public API).

Native assets are priced directly. ERC-20 tokens are priced by contract address
so token balances can be valued in USD without an operator-supplied key.
"""
from __future__ import annotations

from .. import config
from . import http

COIN_IDS = {
    "BTC": "bitcoin",
    "ETH": "ethereum",
    "LTC": "litecoin",
    "DOGE": "dogecoin",
    "TRX": "tron",
    "SOL": "solana",
    "XRP": "ripple",
}

_NATIVE_CACHE: dict[str, float] = {}


async def native_prices(currencies: list[str]) -> dict[str, dict]:
    """Return {chain_symbol: {usd, change_24h, market_cap, image}}."""
    ids = [COIN_IDS[c] for c in currencies if c in COIN_IDS]
    if not ids:
        return {}
    headers = {}
    if config.COINGECKO_API_KEY:
        headers["x-cg-demo-api-key"] = config.COINGECKO_API_KEY

    # simple/price is the most reliable keyless tier; markets adds metadata.
    try:
        simple = await http.fetch_json(
            "https://api.coingecko.com/api/v3/simple/price",
            params={
                "ids": ",".join(ids),
                "vs_currencies": "usd",
                "include_24hr_change": "true",
                "include_market_cap": "true",
            },
            headers=headers,
            ttl=120,
        )
    except Exception:
        simple = {}
    markets = {}
    try:
        rows = await http.fetch_json(
            "https://api.coingecko.com/api/v3/coins/markets",
            params={"vs_currency": "usd", "ids": ",".join(ids), "price_change_percentage": "24h"},
            headers=headers,
            ttl=300,
        )
        markets = {row.get("id"): row for row in rows if isinstance(row, dict)}
    except Exception:
        markets = {}

    out: dict[str, dict] = {}
    for chain, coin_id in COIN_IDS.items():
        sp = simple.get(coin_id) if isinstance(simple, dict) else None
        mk = markets.get(coin_id)
        if not sp and not mk:
            continue
        out[chain] = {
            "usd": (sp or {}).get("usd") if sp else mk.get("current_price"),
            "change_24h": (sp or {}).get("usd_24h_change") if sp else mk.get("price_change_percentage_24h"),
            "market_cap": (sp or {}).get("usd_market_cap") if sp else mk.get("market_cap"),
            "rank": (mk or {}).get("market_cap_rank"),
            "image": (mk or {}).get("image"),
            "high_24h": (mk or {}).get("high_24h"),
            "low_24h": (mk or {}).get("low_24h"),
            "source": "CoinGecko",
        }

    # Coinbase public rates keep valuations working when CoinGecko throttles.
    missing = [c for c in currencies if c in COIN_IDS and c not in out]
    if missing:
        fallback = await coinbase_rates(missing)
        for chain, price in fallback.items():
            out[chain] = {"usd": price, "change_24h": None, "source": "Coinbase"}

    # Kraken is a second independent fallback (covers assets Coinbase omits, e.g. TRX).
    still_missing = [c for c in currencies if c in COIN_IDS and c not in out]
    if still_missing:
        fallback = await kraken_rates(still_missing)
        for chain, price in fallback.items():
            out[chain] = {"usd": price, "change_24h": None, "source": "Kraken"}
    return out


KRAKEN_PAIRS = {
    "BTC": "XBTUSD",
    "ETH": "ETHUSD",
    "LTC": "LTCUSD",
    "DOGE": "DOGEUSD",
    "TRX": "TRXUSD",
    "SOL": "SOLUSD",
    "XRP": "XRPUSD",
}


async def kraken_rates(currencies: list[str]) -> dict[str, float]:
    """Spot USD prices from Kraken's public ticker."""
    pairs = [KRAKEN_PAIRS[c] for c in currencies if c in KRAKEN_PAIRS]
    if not pairs:
        return {}
    try:
        data = await http.fetch_json(
            "https://api.kraken.com/0/public/Ticker",
            params={"pair": ",".join(pairs)},
            ttl=120,
        )
    except Exception:
        return {}
    result = (data or {}).get("result") or {}
    # Kraken returns canonical pair names (e.g. XBTUSD -> XXBTZUSD), so match
    # by the currency contained in the returned key rather than by request order.
    out: dict[str, float] = {}
    for chain in currencies:
        pair = KRAKEN_PAIRS.get(chain)
        if not pair:
            continue
        base = pair[:-3]  # strip "USD"
        candidates = {pair, f"X{base}ZUSD", f"X{base}USD", f"{base}ZUSD"}
        for key, value in result.items():
            if key in candidates:
                try:
                    out[chain] = float(value["c"][0])
                except (KeyError, IndexError, TypeError, ValueError):
                    pass
                break
    return out


async def coinbase_rates(currencies: list[str]) -> dict[str, float]:
    """Spot USD prices from the Coinbase public exchange-rates endpoint."""
    try:
        data = await http.fetch_json(
            "https://api.coinbase.com/v2/exchange-rates",
            params={"currency": "USD"},
            ttl=120,
        )
    except Exception:
        return {}
    rates = ((data or {}).get("data") or {}).get("rates") or {}
    out: dict[str, float] = {}
    for chain in currencies:
        symbol = chain if chain != "TRX" else "TRX"
        rate = rates.get(symbol)
        if not rate:
            continue
        try:
            out[chain] = 1 / float(rate)
        except (TypeError, ValueError, ZeroDivisionError):
            continue
    return out


async def token_price_eth(contracts) -> dict:
    """Price ERC-20 tokens by contract address. Returns {contract_lower: {...}}."""
    if isinstance(contracts, str):
        contracts = [contracts]
    contracts = [c.lower() for c in contracts if c]
    if not contracts:
        return {}
    try:
        data = await http.fetch_json(
            "https://api.coingecko.com/api/v3/simple/token_price/ethereum",
            params={
                "contract_addresses": ",".join(contracts[:60]),
                "vs_currencies": "usd",
                "include_24hr_change": "true",
            },
            ttl=180,
        )
    except Exception:
        return {}
    out = {}
    for contract, entry in (data or {}).items():
        out[contract.lower()] = {
            "usd": entry.get("usd"),
            "change_24h": entry.get("usd_24h_change"),
        }
    return out


async def token_price_solana(mints) -> dict:
    """Price SPL tokens by mint address."""
    if isinstance(mints, str):
        mints = [mints]
    mints = [m for m in mints if m]
    if not mints:
        return {}
    try:
        data = await http.fetch_json(
            "https://api.coingecko.com/api/v3/simple/token_price/solana",
            params={
                "contract_addresses": ",".join(mints[:60]),
                "vs_currencies": "usd",
                "include_24hr_change": "true",
            },
            ttl=180,
        )
    except Exception:
        return {}
    out = {}
    for mint, entry in (data or {}).items():
        out[mint] = {"usd": entry.get("usd"), "change_24h": entry.get("usd_24h_change")}
    return out


async def token_price_tron(contracts) -> dict:
    """Price TRC-20 tokens by contract address."""
    if isinstance(contracts, str):
        contracts = [contracts]
    contracts = [c for c in contracts if c]
    if not contracts:
        return {}
    try:
        data = await http.fetch_json(
            "https://api.coingecko.com/api/v3/simple/token_price/tron",
            params={
                "contract_addresses": ",".join(contracts[:60]),
                "vs_currencies": "usd",
                "include_24hr_change": "true",
            },
            ttl=180,
        )
    except Exception:
        return {}
    out = {}
    for contract, entry in (data or {}).items():
        out[contract] = {"usd": entry.get("usd"), "change_24h": entry.get("usd_24h_change")}
    return out
