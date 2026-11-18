"""Runtime configuration for the OSINT backend.

Values are read from the environment so operators can point the tool at
higher-throughput providers or private RPC nodes without editing code.
"""
from __future__ import annotations

import os

# --- Server -----------------------------------------------------------------
HOST = os.getenv("OSINT_HOST", "0.0.0.0")
PORT = int(os.getenv("OSINT_PORT", "8000"))

# --- Outbound HTTP ----------------------------------------------------------
HTTP_TIMEOUT = float(os.getenv("OSINT_HTTP_TIMEOUT", "15"))
HTTP_RETRIES = int(os.getenv("OSINT_HTTP_RETRIES", "3"))
USER_AGENT = os.getenv(
    "OSINT_USER_AGENT",
    "ChainLens-OSINT/1.0 (+defensive blockchain analytics)",
)

# --- Optional provider keys -------------------------------------------------
# Every provider used by the tool has a working keyless tier. These are only
# used to raise rate limits when the operator supplies them.
COINGECKO_API_KEY = os.getenv("COINGECKO_API_KEY", "")
BLOCKCHAIR_API_KEY = os.getenv("BLOCKCHAIR_API_KEY", "")
TRONGRID_API_KEY = os.getenv("TRONGRID_API_KEY", "")
ETHPLORER_API_KEY = os.getenv("ETHPLORER_API_KEY", "freekey")

# --- Ethereum JSON-RPC endpoints (tried in order) ---------------------------
ETH_RPC_URLS = [
    u.strip()
    for u in os.getenv(
        "OSINT_ETH_RPC_URLS",
        ",".join(
            [
                "https://ethereum-rpc.publicnode.com",
                "https://1rpc.io/eth",
                "https://eth.drpc.org",
                "https://cloudflare-eth.com",
            ]
        ),
    ).split(",")
    if u.strip()
]

# --- Esplora-compatible explorers (Blockstream stack) -----------------------
EXPLORERS = {
    "BTC": "https://blockstream.info/api",
    "LTC": "https://litecoinspace.org/api",
}

# --- Cache ------------------------------------------------------------------
CACHE_DIR = os.getenv("OSINT_CACHE_DIR", os.path.join(os.path.dirname(__file__), "..", "data", "cache"))
CACHE_TTL = int(os.getenv("OSINT_CACHE_TTL", "300"))  # seconds

# --- Sanctions --------------------------------------------------------------
OFAC_BASE = (
    "https://raw.githubusercontent.com/0xB10C/"
    "ofac-sanctioned-digital-currency-addresses/lists"
)
OFAC_LISTS = {
    "BTC": "sanctioned_addresses_XBT.txt",
    "ETH": "sanctioned_addresses_ETH.txt",
    "LTC": "sanctioned_addresses_LTC.txt",
    "DOGE": "sanctioned_addresses_DOGE.txt",
    "XRP": "sanctioned_addresses_XRP.txt",
}
OFAC_TTL = int(os.getenv("OSINT_OFAC_TTL", str(24 * 3600)))

# --- Risk scoring weights ---------------------------------------------------
RISK_WEIGHTS = {
    "sanctioned": 100,
    "mixer": 55,
    "darkweb": 55,
    "phishing": 45,
    "money_laundering": 45,
    "cybercrime": 40,
    "stolen": 40,
    "blackmail": 35,
    "fake_kyc": 25,
    "malicious_contracts": 20,
    "gas_abuse": 10,
}
