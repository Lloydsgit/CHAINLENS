"""Address clustering: related-address and behavioural-pattern detection.

Address clustering is the step from "here is one address" to "here is one
actor". This module implements only the signals that can be defended from the
data a single-address report already contains, and labels every one of them as
a *pattern*, never as proof of common ownership.

Signals implemented (all from the wallet's own recent transactions):

* **Batch send.** Several distinct recipients in the same block. Legitimate for
  payroll, airdrops and exchange withdrawals, and equally used by mixers and
  scammers to fan out. The pattern is reported; the intent is not guessed.
* **Repeat funder.** One address repeatedly funding this wallet. A shared
  funder is a real, if circumstantial, link: it is one of the classic
  common-ownership heuristics, and it is wrong often enough that it must never
  be presented as fact.
* **Round-number transfers.** Transfers of exact round amounts (1, 10, 100 ETH)
  are more often scripted or exchange-driven than hand-made. Weak, reported as
  a hint.

What is deliberately *not* claimed: that any two addresses belong to the same
person. On-chain data supports *hypotheses*, and this module produces exactly
that, with the confounders attached.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Optional

# A batch is "several" recipients in one block. Two is a coincidence.
_BATCH_MIN = 3
# A funder is "repeated" after this many separate funding transactions.
_FUNDER_MIN = 2
# Round amounts worth noticing, in the chain's native unit.
_ROUND_AMOUNTS = (1, 5, 10, 20, 50, 100, 500, 1000)


def _is_round(value: float) -> bool:
    if value <= 0:
        return False
    return any(abs(value - r) < 1e-9 for r in _ROUND_AMOUNTS)


def analyze(transactions: list, address: str, *, native_symbol: str = "ETH") -> Optional[dict]:
    """Derive behavioural clustering signals from a wallet's transactions."""
    addr = address.lower()
    rows = [t for t in (transactions or []) if isinstance(t, dict) and (t.get("from") or t.get("to"))]
    if not rows:
        return None

    batches: dict = defaultdict(set)
    funders: dict = defaultdict(lambda: {"tx_count": 0, "total": 0.0})
    round_txs: list = []

    for tx in rows:
        frm = (tx.get("from") or "").lower()
        to = (tx.get("to") or "").lower()
        value = tx.get("value") or 0
        try:
            value = float(value)
        except Exception:
            value = 0.0

        if frm == addr and to and to != addr:
            block = tx.get("block") or tx.get("block_number")
            if block is not None:
                batches[block].add(to)
            if _is_round(value):
                round_txs.append({"to": to, "value": value, "timestamp": tx.get("timestamp")})
        elif to == addr and frm and frm != addr:
            entry = funders[frm]
            entry["tx_count"] += 1
            entry["total"] += value

    signals: list[dict] = []

    burst = [
        {"block": b, "recipients": len(rs), "addresses": sorted(rs)[:8]}
        for b, rs in batches.items()
        if len(rs) >= _BATCH_MIN
    ]
    burst.sort(key=lambda x: -x["recipients"])
    if burst:
        signals.append(
            {
                "type": "batch_send",
                "confidence": "medium",
                "label": "Batch send (fan-out)",
                "detail": f"{len(burst)} block(s) with {_BATCH_MIN}+ distinct recipients",
                "items": burst[:6],
                "caveat": "Batch sends are normal for payroll, airdrops and exchange withdrawals, and are also used to fan out funds.",
            }
        )

    repeat_funders = [
        {"address": a, "tx_count": v["tx_count"], "total": round(v["total"], 6)}
        for a, v in funders.items()
        if v["tx_count"] >= _FUNDER_MIN
    ]
    repeat_funders.sort(key=lambda x: -x["tx_count"])
    if repeat_funders:
        signals.append(
            {
                "type": "repeat_funder",
                "confidence": "low",
                "label": "Repeat funder",
                "detail": f"{len(repeat_funders)} address(es) funded this wallet more than once",
                "items": repeat_funders[:6],
                "caveat": "A shared funder is circumstantial evidence of a link, not proof of common ownership. Exchanges and services fund many unrelated users.",
            }
        )

    if len(round_txs) >= 3:
        signals.append(
            {
                "type": "round_amounts",
                "confidence": "low",
                "label": "Round-number transfers",
                "detail": f"{len(round_txs)} transfer(s) of exact round amounts",
                "items": round_txs[:6],
                "caveat": "Round amounts suggest scripted or exchange-driven activity, but people send round numbers too.",
            }
        )

    if not signals:
        return {
            "available": True,
            "signals": [],
            "summary": "No clustering pattern stood out in the sampled transactions.",
        }

    return {
        "available": True,
        "sample": len(rows),
        "native_symbol": native_symbol,
        "signals": signals,
        "signal_count": len(signals),
        "summary": _summary(signals),
        "caveat": (
            "Clustering produces hypotheses, not identifications. Two addresses sharing a funder or "
            "transacting in the same block are not proven to share an owner."
        ),
    }


def _summary(signals: list) -> str:
    names = [s["label"] for s in signals]
    return "Patterns observed: " + ", ".join(names) + "."
