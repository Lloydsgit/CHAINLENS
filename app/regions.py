"""Timezone -> possible operating regions.

The activity clock in ``txorigin`` scores candidate UTC offsets. This module
turns those offsets into the *places on Earth* that share them, so an analyst
gets a map of plausible operating regions rather than a bare "UTC+01:00".

Everything is derived from the system timezone database
(``/usr/share/zoneinfo/zone1970.tab`` for zone -> country -> coordinates and
``iso3166.tab`` for country names). Nothing is hardcoded: if tzdata is
installed this works offline and stays current with the tz database.

Two deliberate honesty choices:

* No invented probabilities. Half the planet shares any given offset, and a
  small transaction sample cannot rank one country over another. The output
  lists *which* regions and countries share the inferred active hours, grouped
  by IANA region, and never claims a ranking it cannot support.
* The result is a set of possibilities, not a location. It carries the
  confounders and a confidence derived only from how sharply the offsets fit.
"""
from __future__ import annotations

from datetime import datetime
from typing import Iterable, Optional

ZONE_TAB = "/usr/share/zoneinfo/zone1970.tab"
ISO_TAB = "/usr/share/zoneinfo/iso3166.tab"

# Territories with no resident population: an address is not operated from a
# research station or an uninhabited island.
_UNINHABITED = {"AQ", "BV", "HM", "TF", "GS", "UM", "IO", "PN", "TK", "NU", "NF", "CX", "CC"}

# IANA zone names always begin with one of these area prefixes. Grouping by the
# prefix is accurate where a country's coordinates are not (several unrelated
# countries can share one zone row).
_AREA_REGION = {
    "Africa": "Africa",
    "America": "Americas",
    "Asia": "Asia",
    "Australia": "Oceania",
    "Pacific": "Oceania",
    "Europe": "Europe",
    "Indian": "Indian Ocean",
    "Atlantic": "Atlantic",
}

_zones: Optional[list[dict]] = None
_country_names: Optional[dict[str, str]] = None


def _load_countries() -> dict[str, str]:
    global _country_names
    if _country_names is not None:
        return _country_names
    names: dict[str, str] = {}
    try:
        with open(ISO_TAB, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2:
                    names[parts[0]] = parts[1]
    except Exception:
        pass
    _country_names = names
    return names


def _parse_coord(raw: str) -> Optional[tuple[float, float]]:
    """Parse a zone1970 coordinate like '+4230+00131' into (lat, lon).

    The format is +-DDMM+-DDDMM (degrees and minutes only, no seconds).
    """
    if len(raw) < 11:
        return None
    try:
        lat = int(raw[0:3]) + int(raw[3:5]) / 60
        lon = int(raw[6:9]) + int(raw[9:11]) / 60
    except Exception:
        return None
    if raw[0] == "-":
        lat = -lat
    if raw[5] == "-":
        lon = -lon
    return lat, lon


def _load_zones() -> list[dict]:
    global _zones
    if _zones is not None:
        return _zones
    out: list[dict] = []
    try:
        with open(ZONE_TAB, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 3:
                    continue
                coord = _parse_coord(parts[1])
                if not coord:
                    continue
                countries = [c for c in parts[0].split(",") if c not in _UNINHABITED]
                if not countries:
                    continue
                region = _AREA_REGION.get(parts[2].split("/", 1)[0])
                if not region:
                    continue
                out.append(
                    {
                        "countries": countries,
                        "lat": coord[0],
                        "lon": coord[1],
                        "zone": parts[2],
                        "region": region,
                    }
                )
    except Exception:
        pass
    _zones = out
    return out


def _offset_of(zone: str) -> Optional[float]:
    try:
        import zoneinfo

        return datetime.now(zoneinfo.ZoneInfo(zone)).utcoffset().total_seconds() / 3600
    except Exception:
        return None


def _offset_key(off: float) -> float:
    """Snap an offset to the nearest 15 minutes so float noise does not split it."""
    return round(off * 4) / 4


def _offset_label(off: float) -> str:
    sign = "+" if off >= 0 else "-"
    a = abs(off)
    hours = int(a)
    minutes = int(round((a - hours) * 60))
    return f"UTC{sign}{hours:02d}:{minutes:02d}"


def _flag(code: str) -> str:
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


def possible_regions(
    offset_scores: Iterable[tuple[float, float]],
    *,
    tolerance: float = 0.06,
    max_points: int = 40,
) -> dict:
    """Map scored UTC offsets to the regions and countries that share them.

    ``offset_scores`` is an iterable of ``(offset_hours, fit)`` best-first.
    Offsets within ``tolerance`` of the best fit are treated as equally
    plausible, because a small sample cannot separate them.
    """
    scores = [(float(o), float(f)) for o, f in offset_scores]
    if not scores:
        return {"available": False, "reason": "no timezone signal"}
    scores.sort(key=lambda x: -x[1])
    best = scores[0][1]
    band = [(o, f) for o, f in scores if f >= best - tolerance]

    zones = _load_zones()
    names = _load_countries()
    if not zones:
        return {"available": False, "reason": "timezone database not available"}

    by_offset: dict[float, list[dict]] = {}
    for z in zones:
        off = _offset_of(z["zone"])
        if off is None:
            continue
        by_offset.setdefault(_offset_key(off), []).append(z)

    matched_offsets: list[str] = []
    matched_zones: list[dict] = []
    for off, _fit in band:
        zs = by_offset.get(_offset_key(off))
        if not zs:
            continue
        matched_offsets.append(_offset_label(off))
        matched_zones.extend(zs)

    if not matched_zones:
        return {
            "available": False,
            "reason": "no timezone zone matched the inferred offsets",
            "offsets_considered": matched_offsets,
        }

    regions: dict[str, dict] = {}
    for z in matched_zones:
        reg = regions.setdefault(
            z["region"], {"region": z["region"], "countries": set(), "points": [], "zones": 0}
        )
        reg["zones"] += 1
        reg["countries"].update(z["countries"])
        if len(reg["points"]) < max_points:
            reg["points"].append([round(z["lat"], 3), round(z["lon"], 3)])

    out_regions = []
    for reg in sorted(regions.values(), key=lambda r: -r["zones"]):
        codes = sorted(reg["countries"])
        out_regions.append(
            {
                "region": reg["region"],
                "zone_count": reg["zones"],
                "country_count": len(codes),
                "countries": [{"code": c, "name": names.get(c, c), "flag": _flag(c)} for c in codes],
                "points": reg["points"],
            }
        )

    confidence = "low"
    if best >= 0.85 and len(band) <= 2:
        confidence = "medium"

    return {
        "available": True,
        "basis": "activity-clock offsets from block timestamps",
        "offsets_considered": matched_offsets,
        "best_fit": round(best, 3),
        "confidence": confidence,
        "regions": out_regions,
        "region_count": len(out_regions),
        "country_count": len({c["code"] for r in out_regions for c in r["countries"]}),
        "caveat": (
            "These are the places that share the address's inferred active hours, not a "
            "location. A single offset spans continents, many countries share one offset, "
            "and bots, exchanges and automated strategies all break the waking-hours "
            "assumption. Treat this as a lead to narrow, never as a conclusion."
        ),
    }
