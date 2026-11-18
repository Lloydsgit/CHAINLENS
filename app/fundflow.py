"""Fund-flow tracing and taint exposure.

Balances tell you what an address *has*. An investigator needs what it *touched*:
where value came from, where it went, and whether any of that flow passes through
a sanctioned or high-risk entity. This module builds that view.

Two outputs:

* **Ego network.** Counterparties ranked by volume, with direction (in/out),
  transaction counts and any authoritative label. This is the "who does this
  address deal with" answer.
* **Taint exposure.** Counterparties that are themselves sanctioned, mixers, or
  flagged by address-security screening. Exposure is reported as *direct*
  (the address transacted with the tainted party) and, when a bounded second
  hop is run, as *indirect* (a counterparty of a counterparty is tainted).

Honesty rules enforced here:

* A taint hit is a *fact about a transaction*, not proof of intent. A dust
  transfer from a sanctioned address taints nothing meaningful, so exposure is
  weighted by value and labelled with the amounts involved.
* Indirect exposure is explicitly labelled as indirect and given a lower weight;
  one hop of separation through a shared exchange is extremely common.
* We never claim a counterparty is a person. Labels are the source's words.
"""
from __future__ import annotations

from typing import Optional

from . import labels

# Dust below this many native units is ignored when judging taint severity, so a
# spam/dust attack cannot make a clean wallet look exposed.
_DUST_NATIVE = 1e-6
# Maximum counterparties to run the (more expensive) second hop from.
_SECOND_HOP_LIMIT = 4


def _label_for(address: str) -> Optional[dict]:
    return labels.label_eth(address)


def _risk_of_label(label: Optional[dict]) -> Optional[str]:
    if not label:
        return None
    category = (label.get("category") or "").lower()
    if category in ("mixer", "darkweb", "phishing", "scam", "sanctioned"):
        return category
    return None


def build_ego_network(
    address: str,
    *,
    transactions: Optional[list] = None,
    token_transfers: Optional[list] = None,
    max_nodes: int = 40,
) -> dict:
    """Rank counterparties by value and transaction count."""
    addr = address.lower()
    nodes: dict[str, dict] = {}

    def touch(other: str, direction: str, value: float, symbol: str, kind: str):
        if not other or other == addr:
            return
        node = nodes.setdefault(
            other,
            {
                "address": other,
                "tx_count": 0,
                "in_native": 0.0,
                "out_native": 0.0,
                "tokens_touched": set(),
                "kinds": set(),
            },
        )
        node["tx_count"] += 1
        node["kinds"].add(kind)
        if symbol:
            node["tokens_touched"].add(symbol)
        if kind == "native" and value:
            node[f"{direction}_native"] += value

    for tx in transactions or []:
        if not isinstance(tx, dict):
            continue
        frm = (tx.get("from") or "").lower()
        to = (tx.get("to") or "").lower()
        if addr not in (frm, to):
            continue
        direction = "in" if to == addr else "out"
        other = frm if direction == "in" else to
        try:
            value = float(tx.get("value") or 0)
        except (TypeError, ValueError):
            value = 0.0
        touch(other, direction, value, "native", "native")

    for ev in token_transfers or []:
        if not isinstance(ev, dict):
            continue
        frm = (ev.get("from") or "").lower()
        to = (ev.get("to") or "").lower()
        if addr not in (frm, to):
            continue
        direction = "in" if to == addr else "out"
        other = frm if direction == "in" else to
        symbol = ((ev.get("token") or {}) or {}).get("symbol") if isinstance(ev.get("token"), dict) else None
        touch(other, direction, 0.0, symbol or "", "token")

    out = []
    for node in nodes.values():
        label = _label_for(node["address"])
        node = {
            **node,
            "tokens_touched": sorted(t for t in node["tokens_touched"] if t),
            "kinds": sorted(node["kinds"]),
            "native_in": node["in_native"],
            "native_out": node["out_native"],
            "net_native": node["in_native"] - node["out_native"],
            "label": (label or {}).get("name"),
            "label_category": (label or {}).get("category"),
            "label_jurisdiction": (label or {}).get("jurisdiction"),
        }
        node.pop("in_native", None)
        node.pop("out_native", None)
        out.append(node)

    out.sort(key=lambda n: (n["native_in"] + n["native_out"], n["tx_count"]), reverse=True)
    return {"counterparty_count": len(out), "nodes": out[:max_nodes]}


def assess_taint(
    address: str,
    ego: dict,
    *,
    sanctions_hits: Optional[set] = None,
    goplus_by_addr: Optional[dict] = None,
    indirect: Optional[list] = None,
) -> dict:
    """Flag direct and indirect exposure to tainted counterparties.

    ``sanctions_hits`` is the set of lowercased addresses that appear on the
    OFAC SDN list for this chain; ``goplus_by_addr`` maps an address to its
    GoPlus flags; ``indirect`` is the output of :func:`second_hop`.
    """
    sanctions_hits = sanctions_hits or set()
    goplus_by_addr = goplus_by_addr or {}

    exposures: list[dict] = []
    for node in ego.get("nodes", []):
        other = node["address"]
        reasons: list[dict] = []

        if other in sanctions_hits:
            reasons.append({"kind": "sanctions", "detail": "counterparty is on the OFAC SDN list", "severity": "critical"})

        label = _label_for(other)
        label_risk = _risk_of_label(label)
        if label_risk:
            reasons.append(
                {
                    "kind": label_risk,
                    "detail": f"counterparty is labelled '{label['name']}'",
                    "severity": "critical" if label_risk == "sanctioned" else "high",
                }
            )

        for flag in (goplus_by_addr.get(other) or {}).get("flags", []):
            reasons.append(
                {
                    "kind": "security",
                    "detail": f"counterparty flagged: {flag.get('label')}",
                    "severity": "high",
                }
            )

        if not reasons:
            continue

        volume = (node.get("native_in") or 0) + (node.get("native_out") or 0)
        severity = max((r["severity"] for r in reasons), key=lambda s: {"critical": 3, "high": 2, "medium": 1}.get(s, 0))
        # A dust-only link is reported but downgraded: it is a real edge, but not
        # evidence of meaningful exposure.
        if volume < _DUST_NATIVE:
            severity = "medium" if severity == "critical" else "low"

        exposures.append(
            {
                "address": other,
                "hop": 1,
                "direction": "in" if (node.get("native_in") or 0) >= (node.get("native_out") or 0) else "out",
                "native_in": node.get("native_in"),
                "native_out": node.get("native_out"),
                "tx_count": node.get("tx_count"),
                "label": node.get("label"),
                "reasons": reasons,
                "severity": severity,
            }
        )

    for item in indirect or []:
        exposures.append({**item, "hop": 2})

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    exposures.sort(key=lambda e: (order.get(e["severity"], 9), -(e.get("tx_count") or 0)))

    direct = [e for e in exposures if e["hop"] == 1]
    indirect_hits = [e for e in exposures if e["hop"] == 2]
    worst = min((e["severity"] for e in exposures), key=lambda s: order.get(s, 9), default=None)

    return {
        "checked": True,
        "exposure_count": len(exposures),
        "direct_count": len(direct),
        "indirect_count": len(indirect_hits),
        "worst_severity": worst,
        "exposures": exposures[:25],
        "note": (
            "Exposure means this address transacted with a flagged counterparty. It is not a "
            "judgement about intent: dust attacks, shared exchange deposit addresses and one-hop "
            "separation all produce links that are not meaningful. Indirect (2-hop) exposure is "
            "common and weak."
        ),
    }


async def second_hop(
    ego: dict,
    *,
    fetch_transactions,
    sanctions_hits: Optional[set] = None,
    labels_lookup=None,
    max_from: int = _SECOND_HOP_LIMIT,
) -> list:
    """Check whether the largest counterparties themselves touch tainted entities.

    ``fetch_transactions`` is an async callable ``(address) -> list[tx]`` supplied
    by the caller so this module stays provider-agnostic.
    """
    import asyncio

    sanctions_hits = sanctions_hits or set()
    top = ego.get("nodes", [])[:max_from]
    if not top:
        return []

    async def probe(node):
        other = node["address"]
        try:
            txs = await fetch_transactions(other)
        except Exception:
            return []
        hits = []
        for tx in txs or []:
            if not isinstance(tx, dict):
                continue
            frm = (tx.get("from") or "").lower()
            to = (tx.get("to") or "").lower()
            for party in (frm, to):
                if not party or party == other:
                    continue
                if party in sanctions_hits:
                    hits.append(
                        {
                            "address": other,
                            "via": party,
                            "via_label": (labels_lookup(party) if labels_lookup else None) or "OFAC SDN listed",
                            "reasons": [
                                {
                                    "kind": "sanctions",
                                    "detail": f"counterparty transacts with OFAC-listed {party[:10]}…",
                                    "severity": "high",
                                }
                            ],
                            "severity": "high",
                        }
                    )
                    break
            if hits:
                break
        return hits

    results = await asyncio.gather(*(probe(n) for n in top))
    flat = [hit for group in results for hit in group]
    # Dedupe by (address, via).
    seen = set()
    out = []
    for hit in flat:
        key = (hit["address"], hit["via"])
        if key in seen:
            continue
        seen.add(key)
        out.append(hit)
    return out
