"""Entity attribution: assemble everything public that says *who* an address is.

No single source answers "who is this". This module fuses them into one dossier
and, critically, records the *source and strength* of every claim so a weak hint
never reads like a confirmed identity:

* curated labels (this project's conservative list)
* the explorer's own label set (Blockscout/Open Labels Initiative tags), which
  carries entity names, category tags and verified service domains
* reverse ENS (primary name + socials/website from the ENS profile)
* GoPlus address-security flags
* OFAC SDN screening
* the scam / reputation flags the explorer attaches to the address

Attribution is deliberately graded. ``confirmed`` requires an authoritative
source (sanctions list, explorer entity tag, curated label). A reverse-ENS name
is ``probable``. Anything derived from behaviour is ``possible`` and belongs to
the clustering module, not here.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from .. import labels

# Tag types that name a real-world entity or service rather than describe a
# token mechanically. "generic" tags like "Token Contract" are noise for
# attribution and are dropped.
_ENTITY_TAG_TYPES = {"name", "classifier"}
_NOISE_SLUGS = {
    "tokencontract",
    "token",
    "erc20",
    "erc721",
    "erc1155",
    "stablecoin",
    "contract",
    "verifiedcontract",
}

_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.I)


def _clean(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _extract_tags(party: dict) -> dict:
    """Pull entity names, categories and verified domains from an explorer party.

    Blockscout attaches its label set to the ``from``/``to`` objects of a
    transaction. The shape varies a little between instances, so read defensively.
    """
    names: list[str] = []
    categories: list[str] = []
    domains: list[str] = []
    notes: list[str] = []

    metadata = party.get("metadata") or {}
    for tag in metadata.get("tags") or []:
        if not isinstance(tag, dict):
            continue
        tag_type = (tag.get("tagType") or "").lower()
        slug = (tag.get("slug") or "").replace("-", "").replace("_", "").lower()
        name = _clean(tag.get("name"))
        if tag_type in _ENTITY_TAG_TYPES and name and slug not in _NOISE_SLUGS:
            if name not in names:
                names.append(name)
        elif tag_type == "generic" and name and slug not in _NOISE_SLUGS:
            if name not in categories:
                categories.append(name)
        meta = tag.get("meta") or {}
        for domain in meta.get("verifiedDomains") or []:
            domain = _clean(domain)
            if domain and _DOMAIN_RE.match(domain) and domain not in domains:
                domains.append(domain)
        desc = _clean(meta.get("tooltipDescription"))
        if desc and desc not in notes:
            notes.append(desc)

    # ``name`` on the party object itself is the explorer's display name.
    display = _clean(party.get("name"))
    if display and display not in names:
        names.insert(0, display)

    return {"names": names, "categories": categories, "domains": domains, "notes": notes}


def attribute(
    address: str,
    *,
    chain: str = "ETH",
    explorer_party: Optional[dict] = None,
    reverse_ens: Optional[dict] = None,
    goplus: Optional[dict] = None,
    ofac: Optional[dict] = None,
    is_contract: Optional[bool] = None,
    counterparty_count: int = 0,
) -> dict:
    """Fuse attribution sources into one graded dossier.

    ``explorer_party`` is the ``from``/``to`` object for this address from any
    Blockscout response; it is the richest free source of entity labels.
    """
    addr = address.lower()
    claims: list[dict] = []

    def claim(kind: str, value: str, source: str, confidence: str, detail: Optional[str] = None):
        claims.append(
            {
                "kind": kind,
                "value": value,
                "source": source,
                "confidence": confidence,
                "detail": detail,
            }
        )

    # --- curated label (authoritative, hand-checked) -------------------------
    curated = labels.label_eth(addr)
    if curated:
        claim("label", curated["name"], "curated label list", "confirmed", curated.get("category"))

    # --- explorer entity tags ------------------------------------------------
    tags = _extract_tags(explorer_party or {})
    for name in tags["names"]:
        claim("label", name, f"{chain} explorer label set", "confirmed")
    for category in tags["categories"]:
        claim("category", category, f"{chain} explorer label set", "confirmed")
    for domain in tags["domains"]:
        claim("domain", domain, f"{chain} explorer label set", "confirmed", "verified service domain")
    for note in tags["notes"][:3]:
        claim("note", note, f"{chain} explorer label set", "confirmed")

    # --- reverse ENS ---------------------------------------------------------
    if reverse_ens and isinstance(reverse_ens, dict):
        name = _clean(reverse_ens.get("name"))
        if name:
            claim("ens", name, "reverse ENS record", "probable")

    # --- reputation / scam flags --------------------------------------------
    if explorer_party:
        if explorer_party.get("is_scam"):
            claim("scam_flag", "flagged as scam by explorer", f"{chain} explorer", "confirmed")
        rep = _clean(explorer_party.get("reputation"))
        if rep and rep.lower() not in ("ok", "unknown"):
            claim("reputation", rep, f"{chain} explorer reputation", "confirmed")

    # --- sanctions -----------------------------------------------------------
    if ofac and ofac.get("listed"):
        claim("sanctions", "OFAC SDN listed", ofac.get("source") or "OFAC SDN", "confirmed")

    # --- security flags ------------------------------------------------------
    for flag in (goplus or {}).get("flags") or []:
        if isinstance(flag, dict):
            value = _clean(flag.get("title") or flag.get("detail"))
            if value:
                claim("security", value, "GoPlus Labs", "confirmed")

    # --- structural facts (not identity, but part of the dossier) ------------
    if is_contract:
        claim("type", "smart contract", f"{chain} explorer", "confirmed")

    # --- derived: is this an exchange/service or an individual? -------------
    # Only stated when an authoritative source supports it.
    entity_names = {c["value"].lower() for c in claims if c["kind"] == "label"}
    looks_service = bool(tags["domains"]) or any(
        kw in n for n in entity_names for kw in ("exchange", "binance", "coinbase", "kraken", "okx", "bitfinex", "kucoin", "gate", "huobi", "htx", "bybit", "bitstamp", "gemini")
    )

    # Dedupe claims on (kind, value), keeping the highest-confidence source.
    rank = {"confirmed": 3, "probable": 2, "possible": 1}
    deduped: dict[tuple, dict] = {}
    for c in claims:
        key = (c["kind"], c["value"].lower())
        existing = deduped.get(key)
        if existing is None or rank.get(c["confidence"], 0) > rank.get(existing["confidence"], 0):
            deduped[key] = c
    claims = sorted(deduped.values(), key=lambda c: (-rank.get(c["confidence"], 0), c["kind"]))

    confidence = "confirmed" if any(c["confidence"] == "confirmed" for c in claims) else (
        "probable" if claims else "none"
    )

    return {
        "address": addr,
        "claims": claims,
        "claim_count": len(claims),
        "confidence": confidence,
        "entity_type": "service" if looks_service else ("contract" if is_contract else "individual/unlabelled"),
        "sources": sorted({c["source"] for c in claims}),
        "caveat": (
            "Attribution is only as strong as its source. 'confirmed' means an authoritative "
            "label set or sanctions list names this address; 'probable' is a reverse-ENS name, "
            "which the address owner controls and can set to anything."
        ),
    }
