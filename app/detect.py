"""Input classification: figure out what the analyst pasted in.

Returns a structured target describing the asset class and chain so the
analyzer knows which providers to call. Detection is intentionally strict and
never guesses between ambiguous base58 chains without a recognizable prefix.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
BTC_LEGACY_RE = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
BTC_BECH32_RE = re.compile(r"^bc1[023456789acdefghjklmnpqrstuvwxyz]{11,71}$")
LTC_LEGACY_RE = re.compile(r"^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$")
LTC_BECH32_RE = re.compile(r"^ltc1[023456789acdefghjklmnpqrstuvwxyz]{11,71}$")
DOGE_RE = re.compile(r"^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$")
TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
XRP_RE = re.compile(r"^r[1-9A-HJ-NP-Za-km-z]{24,34}$")
SOL_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
ENS_RE = re.compile(r"^[a-z0-9-_.]+\.eth$", re.IGNORECASE)
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


@dataclass
class Target:
    raw: str
    kind: str  # "address" | "ens" | "ip" | "host" | "unknown"
    chain: Optional[str] = None
    normalized: Optional[str] = None
    notes: list = field(default_factory=list)


def _looks_like_ip(value: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(value)
        return "IPv4" if ip.version == 4 else "IPv6"
    except ValueError:
        return None


def detect(raw: str) -> Target:
    value = (raw or "").strip()
    if not value:
        return Target(raw=value, kind="unknown", notes=["empty input"])

    # --- IP address ---------------------------------------------------------
    ip_version = _looks_like_ip(value)
    if ip_version:
        return Target(raw=value, kind="ip", normalized=value, notes=[ip_version])

    # --- ENS ----------------------------------------------------------------
    if ENS_RE.match(value):
        return Target(raw=value, kind="ens", chain="ETH", normalized=value.lower())

    # --- EVM / Ethereum -----------------------------------------------------
    if ETH_RE.match(value):
        return Target(raw=value, kind="address", chain="ETH", normalized=value.lower())

    # --- Bitcoin ------------------------------------------------------------
    if BTC_BECH32_RE.match(value.lower()):
        return Target(raw=value, kind="address", chain="BTC", normalized=value.lower())
    if BTC_LEGACY_RE.match(value):
        return Target(raw=value, kind="address", chain="BTC", normalized=value)

    # --- Litecoin (checked before DOGE/SOL: distinct prefixes) --------------
    if LTC_BECH32_RE.match(value.lower()):
        return Target(raw=value, kind="address", chain="LTC", normalized=value.lower())
    if LTC_LEGACY_RE.match(value):
        return Target(raw=value, kind="address", chain="LTC", normalized=value)

    # --- Dogecoin -----------------------------------------------------------
    if DOGE_RE.match(value):
        return Target(raw=value, kind="address", chain="DOGE", normalized=value)

    # --- Tron ---------------------------------------------------------------
    if TRON_RE.match(value):
        return Target(raw=value, kind="address", chain="TRON", normalized=value)

    # --- XRP ----------------------------------------------------------------
    if XRP_RE.match(value):
        return Target(raw=value, kind="address", chain="XRP", normalized=value)

    # --- Solana (broad base58 fallback, last) -------------------------------
    if SOL_RE.match(value):
        return Target(
            raw=value,
            kind="address",
            chain="SOL",
            normalized=value,
            notes=["classified as Solana by base58 shape"],
        )

    # --- Hostname -----------------------------------------------------------
    if HOST_RE.match(value):
        return Target(raw=value, kind="host", normalized=value.lower())

    return Target(raw=value, kind="unknown", notes=["unrecognized format"])


def address_chain_family(chain: Optional[str]) -> str:
    """Group chains by the provider family that serves them."""
    if chain in {"ETH"}:
        return "evm"
    if chain in {"BTC", "LTC"}:
        return "esplora"
    if chain == "DOGE":
        return "dogechain"
    if chain == "TRON":
        return "tron"
    if chain == "SOL":
        return "solana"
    if chain == "XRP":
        return "xrp"
    return "unknown"
