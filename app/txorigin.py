"""Transaction-origin analysis: where was a transaction *issued* from?

The blunt truth first: a raw blockchain transaction carries **no IP address and
no location**. There is no "origin" field to read. A signed transaction is
broadcast peer-to-peer to whichever node the sender's wallet happens to be
connected to, and once mined only the signature and payload remain. A
transaction therefore cannot be geolocated the way an HTTP request can.

What *can* be derived legitimately are two weaker but real signals:

1. **The on-chain clock.** Every transaction has a block timestamp (UTC). The
   hours and days an address transacts form a behavioural pattern. If a person
   transacts mostly during their waking hours, the pattern weakly hints at a
   timezone -- never a location, and easily confounded by bots, exchanges and
   automated strategies.
2. **Venue jurisdiction.** When a transaction touches a labelled exchange or
   mixer, that *service* has a documented jurisdiction. This describes where
   the counterparty is regulated or registered -- not where the user is.

Everything here is reported as a hint with its confidence and its confounders,
never as a coordinate.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional

# Offsets to test, in hours. Includes the common half- and quarter-hour zones.
_CANDIDATE_OFFSETS = [
    -10, -9, -8, -7, -6, -5, -4, -3.5, -3, -2, -1, 0, 1, 2, 3, 3.5, 4, 4.5,
    5, 5.5, 5.75, 6, 6.5, 7, 8, 8.75, 9, 9.5, 10, 10.5, 11, 12, 12.75, 13,
]

# The waking-hours window used for the timezone fit. Deliberately generous.
_WAKING_START = 7
_WAKING_END = 24

_EXPLANATION = (
    "A transaction has no IP and no location: it is signed offline and broadcast "
    "peer-to-peer, so there is no origin field to read. Two weaker signals are shown "
    "instead -- the hours the address transacts (a timezone hint) and the jurisdiction "
    "of any exchange or service it touched (the venue's jurisdiction, not the user's)."
)


def _to_dt(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _offset_label(off: float) -> str:
    sign = "+" if off >= 0 else "-"
    a = abs(off)
    hours = int(a)
    minutes = int(round((a - hours) * 60))
    return f"UTC{sign}{hours:02d}:{minutes:02d}"


def _offset_from_label(label: str) -> float:
    """Inverse of ``_offset_label``: 'UTC+05:30' -> 5.5."""
    try:
        body = label.replace("UTC", "").strip()
        sign = -1 if body.startswith("-") else 1
        body = body.lstrip("+-")
        hours, _, minutes = body.partition(":")
        return sign * (int(hours) + (int(minutes) / 60 if minutes else 0))
    except Exception:
        return 0.0


def _score_offsets(dts: list[datetime]) -> list[tuple[float, float]]:
    """Score every candidate offset by share of activity in waking hours."""
    hours = [d.hour for d in dts]
    scored = []
    for off in _CANDIDATE_OFFSETS:
        local = [(h + off) % 24 for h in hours]
        waking = sum(1 for h in local if _WAKING_START <= h < _WAKING_END)
        scored.append((off, waking / len(local)))
    scored.sort(key=lambda x: -x[1])
    return scored


def _histogram(hours: list[int]) -> list[int]:
    hist = [0] * 24
    for h in hours:
        hist[int(h) % 24] += 1
    return hist


def _infer_timezones(dts: list[datetime], min_sample: int = 8, top: int = 3) -> dict:
    if len(dts) < min_sample:
        return {
            "available": False,
            "sample": len(dts),
            "reason": f"needs at least {min_sample} transactions for a timezone hint",
        }
    scored = _score_offsets(dts)

    best = scored[0][1]
    # A band of offsets often scores identically; keep those within 5% of best.
    hints = [
        {"utc_offset": _offset_label(off), "waking_hours_fit": round(fit, 3)}
        for off, fit in scored[:top]
    ]
    return {
        "available": True,
        "sample": len(dts),
        "method": f"share of transactions falling in {_WAKING_START:02d}:00-{_WAKING_END:02d}:00 local time",
        "best_fit": round(best, 3),
        "hints": hints,
        "caveat": (
            "Weak signal, not a location. Bots, exchanges, automated strategies and "
            "late-night activity all break the waking-hours assumption, and many "
            "offsets fit a small sample equally well."
        ),
    }


def _venues(counterparties: list, label_lookup: Callable[[str], Optional[dict]]) -> list[dict]:
    venues = []
    seen = set()
    for cp in counterparties or []:
        addr = (cp.get("address") or "").lower()
        if not addr or addr in seen:
            continue
        lab = label_lookup(addr)
        if not lab or lab.get("category") not in ("exchange", "mixer", "foundation", "infrastructure"):
            continue
        seen.add(addr)
        venues.append(
            {
                "address": cp.get("address"),
                "label": lab.get("name"),
                "category": lab.get("category"),
                "jurisdiction": lab.get("jurisdiction"),
                "tx_count": cp.get("tx_count"),
            }
        )
    venues.sort(key=lambda v: v.get("tx_count") or 0, reverse=True)
    return venues


def analyze(
    timeline: list,
    counterparties: list,
    label_lookup: Callable[[str], Optional[dict]],
    *,
    min_sample: int = 8,
) -> Optional[dict]:
    """Derive honest transaction-origin hints from a report's timeline."""
    from . import regions

    dts = [d for d in (_to_dt(e.get("timestamp")) for e in (timeline or [])) if d]
    if not dts:
        return None
    dts.sort()
    hist = _histogram([d.hour for d in dts])
    peak = max(hist)
    peak_hours = [i for i, c in enumerate(hist) if c == peak and c > 0]
    venues = _venues(counterparties, label_lookup)
    tz = _infer_timezones(dts, min_sample=min_sample)

    # Turn the offset hints into the regions that share those active hours.
    if tz.get("available"):
        offset_scores = [
            (_offset_from_label(h["utc_offset"]), h["waking_hours_fit"]) for h in tz["hints"]
        ]
        # Score the full candidate set so the tolerance band is meaningful.
        full = _score_offsets(dts)
        tz["possible_regions"] = regions.possible_regions(full or offset_scores)
    else:
        tz["possible_regions"] = regions.possible_regions([])

    out: dict = {
        "explanation": _EXPLANATION,
        "sample": len(dts),
        "window": {"first": dts[0].isoformat(), "last": dts[-1].isoformat()},
        "activity_clock_utc": {
            "hours": hist,
            "peak_hours_utc": peak_hours,
            "note": "Count of transactions by hour of day, in UTC.",
        },
        "timezone_hints": tz,
        "venues": venues,
    }
    if venues:
        out["venue_note"] = (
            "Jurisdictions belong to the exchanges/services listed, not to the wallet owner. "
            "Interacting with a US exchange says the service is US-regulated, not that the user is in the US."
        )
    return out
