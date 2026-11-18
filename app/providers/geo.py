"""Network intelligence: multi-source IP geolocation, ASN, anonymity and RDAP.

Several independent geolocation providers are queried concurrently and their
answers are reconciled. The reconciled city/region/country is a majority vote
and the coordinates are the median of the sources, which is far more stable
than trusting any single provider. Agreement between sources drives a
confidence level, so the report shows how trustworthy a location actually is
instead of presenting one provider's guess as fact.
"""
from __future__ import annotations

import asyncio
import math
from typing import Any, Optional

from . import http

_DOH = "https://cloudflare-dns.com/dns-query"
_DOH_HEADERS = {"accept": "application/dns-json"}

# ip-api's free tier only returns a fixed field set.
_IPAPI_FIELDS = (
    "status,message,continent,continentCode,country,countryCode,region,regionName,"
    "city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,"
    "mobile,proxy,hosting,query"
)


def _num(value: Any) -> Optional[float]:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _haversine_km(a: tuple, b: tuple) -> float:
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * 6371.0 * math.asin(min(1.0, math.sqrt(h)))


def _majority(values: list[str]) -> Optional[str]:
    counts: dict[str, int] = {}
    display: dict[str, str] = {}
    for v in values:
        if not v:
            continue
        key = v.strip().lower()
        counts[key] = counts.get(key, 0) + 1
        display.setdefault(key, v.strip())
    if not counts:
        return None
    best = max(counts, key=lambda k: counts[k])
    return display[best]


def _median(values: list[float]) -> Optional[float]:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    mid = len(vals) // 2
    if len(vals) % 2:
        return vals[mid]
    return (vals[mid - 1] + vals[mid]) / 2


# --------------------------------------------------------------------------
# Per-provider parsers. Each returns a normalised dict or None.
# --------------------------------------------------------------------------

def _parse_ipwho(data: dict) -> Optional[dict]:
    if not isinstance(data, dict) or not data.get("success", True):
        return None
    if not data.get("ip"):
        return None
    tz = data.get("timezone") or {}
    conn = data.get("connection") or {}
    sec = data.get("security") or {}
    return {
        "source": "ipwho.is",
        "ip": data.get("ip"),
        "type": data.get("type"),
        "continent": data.get("continent"),
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "region_code": data.get("region_code"),
        "city": data.get("city"),
        "postal": data.get("postal"),
        "latitude": _num(data.get("latitude")),
        "longitude": _num(data.get("longitude")),
        "is_eu": data.get("is_eu"),
        "calling_code": data.get("calling_code"),
        "capital": data.get("capital"),
        "borders": data.get("borders"),
        "flag": data.get("flag"),
        "asn": conn.get("asn"),
        "isp": conn.get("isp"),
        "org": conn.get("org"),
        "asn_domain": conn.get("domain"),
        "timezone_id": tz.get("id"),
        "timezone_utc": tz.get("utc"),
        "local_time": tz.get("current_time"),
        "is_dst": tz.get("is_dst"),
        "anonymity": {
            "proxy": bool(sec.get("proxy")),
            "vpn": bool(sec.get("vpn")),
            "tor": bool(sec.get("tor")),
            "relay": bool(sec.get("relay")),
            "hosting": bool(sec.get("hosting")),
        },
    }


def _parse_ipapi(data: dict) -> Optional[dict]:
    if not isinstance(data, dict) or data.get("status") != "success":
        return None
    as_field = data.get("as") or ""
    asn = as_field.split(" ")[0] if as_field else None
    return {
        "source": "ip-api.com",
        "ip": data.get("query"),
        "type": "IPv6" if ":" in (data.get("query") or "") else "IPv4",
        "continent": data.get("continent"),
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "region_code": data.get("region"),
        "city": data.get("city"),
        "district": data.get("district"),
        "postal": data.get("zip"),
        "latitude": _num(data.get("lat")),
        "longitude": _num(data.get("lon")),
        "asn": asn,
        "as_name": as_field.split(" ", 1)[1] if " " in as_field else None,
        "isp": data.get("isp"),
        "org": data.get("org"),
        "timezone_id": data.get("timezone"),
        "utc_offset_seconds": data.get("offset"),
        "reverse_dns": data.get("reverse"),
        "currency": data.get("currency"),
        "anonymity": {
            "proxy": bool(data.get("proxy")),
            "hosting": bool(data.get("hosting")),
            "mobile": bool(data.get("mobile")),
        },
    }


def _parse_ipinfo(data: dict) -> Optional[dict]:
    if not isinstance(data, dict) or not data.get("ip"):
        return None
    if data.get("bogon"):
        return None
    loc = (data.get("loc") or "").split(",")
    lat = _num(loc[0]) if len(loc) == 2 else None
    lon = _num(loc[1]) if len(loc) == 2 else None
    org = data.get("org") or ""
    asn = None
    as_name = None
    if org.upper().startswith("AS"):
        parts = org.split(" ", 1)
        asn = parts[0]
        as_name = parts[1] if len(parts) > 1 else None
    return {
        "source": "ipinfo.io",
        "ip": data.get("ip"),
        "country": data.get("country"),
        "region": data.get("region"),
        "city": data.get("city"),
        "postal": data.get("postal"),
        "latitude": lat,
        "longitude": lon,
        "asn": asn,
        "as_name": as_name,
        "org": org,
        "timezone_id": data.get("timezone"),
        "reverse_dns": data.get("hostname"),
    }


def _parse_ipapi_is(data: dict) -> Optional[dict]:
    if not isinstance(data, dict) or not data.get("ip"):
        return None
    # The free tier returns a flat object; richer plans nest the same data.
    loc = data.get("location") if isinstance(data.get("location"), dict) else data
    asn_info = data.get("asn") if isinstance(data.get("asn"), dict) else {}
    company = data.get("company") if isinstance(data.get("company"), dict) else {}
    asn_str = asn_info.get("asn") or data.get("asn")
    asn = None
    if asn_str and not isinstance(asn_str, dict):
        asn = f"AS{asn_str}" if not str(asn_str).upper().startswith("AS") else str(asn_str).split(" ")[0]
    return {
        "source": "ipapi.is",
        "ip": data.get("ip"),
        "type": data.get("type"),
        "country": loc.get("country"),
        "country_code": loc.get("country_code") or _iso2(loc.get("country")),
        "region": loc.get("state") or loc.get("region"),
        "city": loc.get("city"),
        "postal": loc.get("zip"),
        "latitude": _num(loc.get("latitude", loc.get("lat"))),
        "longitude": _num(loc.get("longitude", loc.get("lon"))),
        "timezone_id": loc.get("timezone"),
        "continent": loc.get("continent"),
        "asn": asn,
        "as_name": asn_info.get("descr") or (asn_str.split(" ", 1)[1] if isinstance(asn_str, str) and " " in asn_str else None),
        "org": company.get("name") or (data.get("company") if isinstance(data.get("company"), str) else None),
        "isp": asn_info.get("org"),
        "is_eu": loc.get("is_eu_member"),
        "anonymity": {
            "proxy": bool(data.get("is_proxy")),
            "vpn": bool(data.get("is_vpn")),
            "tor": bool(data.get("is_tor")),
            "relay": bool(data.get("is_relay")),
            "hosting": bool(data.get("is_datacenter")),
            "abuser": bool(data.get("is_abuser")),
        },
    }


def _iso2(country_name: Optional[str]) -> Optional[str]:
    """Map a country name to its ISO-3166 alpha-2 code (small built-in table)."""
    if not country_name:
        return None
    table = {
        "united states": "US", "germany": "DE", "united kingdom": "GB",
        "australia": "AU", "netherlands": "NL", "france": "FR", "canada": "CA",
        "japan": "JP", "singapore": "SG", "switzerland": "CH", "sweden": "SE",
        "russia": "RU", "china": "CN", "india": "IN", "brazil": "BR",
        "spain": "ES", "italy": "IT", "ireland": "IE", "poland": "PL",
        "finland": "FI", "norway": "NO", "denmark": "DK", "belgium": "BE",
        "austria": "AT", "south korea": "KR", "hong kong": "HK", "turkey": "TR",
        "ukraine": "UA", "romania": "RO", "czechia": "CZ", "portugal": "PT",
    }
    return table.get(country_name.strip().lower())


async def _safe(coro) -> Optional[Any]:
    try:
        return await coro
    except Exception:
        return None


async def _ipwho(ip: str) -> Optional[dict]:
    return _parse_ipwho(await http.fetch_json(f"https://ipwho.is/{ip}", ttl=900))


async def _ipapi(ip: str) -> Optional[dict]:
    data = await http.fetch_json(
        f"http://ip-api.com/json/{ip}", params={"fields": _IPAPI_FIELDS}, ttl=900
    )
    return _parse_ipapi(data)


async def _ipinfo(ip: str) -> Optional[dict]:
    return _parse_ipinfo(await http.fetch_json(f"https://ipinfo.io/{ip}/json", ttl=900))


async def _ipapi_is(ip: str) -> Optional[dict]:
    return _parse_ipapi_is(await http.fetch_json("https://api.ipapi.is/", params={"q": ip}, ttl=900))


async def lookup_ip(ip: str) -> dict:
    """Query every geo provider concurrently and reconcile the answers."""
    results = await asyncio.gather(
        _safe(_ipwho(ip)),
        _safe(_ipapi(ip)),
        _safe(_ipinfo(ip)),
        _safe(_ipapi_is(ip)),
    )
    records = [r for r in results if r]

    if not records:
        return {"ip": ip, "sources": [], "rdap": await _safe(rdap_ip(ip)) or {}}

    def first(field: str):
        for rec in records:
            if rec.get(field) not in (None, ""):
                return rec[field]
        return None

    country_code = _majority([r.get("country_code") for r in records if r.get("country_code")])
    country = _majority([r.get("country") for r in records if r.get("country")])
    region = _majority([r.get("region") for r in records if r.get("region")])
    city = _majority([r.get("city") for r in records if r.get("city")])

    def _coord_of(rec):
        if rec.get("latitude") is None or rec.get("longitude") is None:
            return None
        return (rec["latitude"], rec["longitude"])

    # Prefer coordinates from providers that agree with the majority city, then
    # majority country. A single provider mislocating an IP cannot drag the
    # pinpoint away from the consensus the way a raw median would.
    agree_city = [r for r in records if (r.get("city") or "").strip().lower() == (city or "").strip().lower()]
    agree_country = [r for r in records if (r.get("country_code") or "").upper() == (country_code or "").upper()]
    pool = agree_city or agree_country or records
    coords = [c for c in (_coord_of(r) for r in pool) if c]
    if not coords:
        coords = [c for c in (_coord_of(r) for r in records) if c]

    lat = _median([c[0] for c in coords])
    lon = _median([c[1] for c in coords])

    all_coords = [c for c in (_coord_of(r) for r in records) if c]
    spread = 0.0
    if len(all_coords) > 1:
        spread = max(
            _haversine_km(a, b) for i, a in enumerate(all_coords) for b in all_coords[i + 1:]
        )

    total = len(records)
    city_votes = len({(r.get("city") or "").strip().lower() for r in records if r.get("city")})
    country_votes = len({(r.get("country_code") or "").strip().lower()
                         for r in records if r.get("country_code")})
    if country_votes <= 1 and city_votes <= 1 and total >= 3:
        level, note = "high", "All sources agree on city and country"
    elif country_votes <= 1 and spread < 100:
        level, note = "high", "Sources agree closely"
    elif country_votes <= 1 and spread < 400:
        level, note = "medium", "Country agreed, city coordinates differ"
    elif country_votes <= 1:
        level, note = "medium", "Country agreed, coordinates vary widely"
    else:
        level, note = "low", "Sources disagree; treat with caution"

    # Anonymity is evidence, not a vote. Tor is authoritative and may stand
    # alone. Other flags (proxy/hosting/vpn/relay/abuser) are noisy on their
    # own -- ip-api in particular flags datacenter IPs as proxies -- so they
    # require corroboration from a second provider. The detail map records who
    # reported what so the UI can show the disagreement.
    anon: dict[str, dict] = {}
    for rec in records:
        for flag, val in (rec.get("anonymity") or {}).items():
            if val:
                entry = anon.setdefault(flag, {"count": 0, "sources": []})
                entry["count"] += 1
                entry["sources"].append(rec.get("source"))
    anonymity = {
        flag: (flag == "tor" or info["count"] >= 2)
        for flag, info in anon.items()
    }
    anonymity_detail = {
        flag: {"reported_by": info["count"], "of": total, "sources": info["sources"]}
        for flag, info in anon.items()
    }

    tz_id = first("timezone_id")
    tz = local_time(tz_id)
    rdap = await _safe(rdap_ip(ip)) or {}
    ptr = first("reverse_dns") or await _safe(reverse_dns(ip))

    # The Tor Project's own exit list is authoritative, so it can raise the
    # flag even when no geolocation provider noticed.
    tor_exit = await _safe(is_tor_exit(ip))
    if tor_exit:
        anonymity["tor"] = True
        anonymity_detail.setdefault("tor", {"reported_by": 1, "of": total, "sources": []})
        anonymity_detail["tor"]["sources"] = list(
            dict.fromkeys(anonymity_detail["tor"].get("sources", []) + ["torproject.org"])
        )
        anonymity_detail["tor"]["reported_by"] = len(anonymity_detail["tor"]["sources"])

    return {
        "ip": ip,
        "type": first("type"),
        "continent": first("continent"),
        "country": country,
        "country_code": country_code,
        "region": region,
        "region_code": first("region_code"),
        "city": city,
        "district": first("district"),
        "postal": first("postal"),
        "latitude": lat,
        "longitude": lon,
        "is_eu": first("is_eu"),
        "calling_code": first("calling_code"),
        "capital": first("capital"),
        "borders": first("borders"),
        "currency": first("currency"),
        "flag": first("flag"),
        "asn": first("asn"),
        "as_name": first("as_name"),
        "isp": first("isp"),
        "org": first("org"),
        "asn_domain": first("asn_domain"),
        "reverse_dns": ptr,
        "timezone_id": tz_id,
        "timezone_utc": first("timezone_utc"),
        "utc_offset": tz.get("utc_offset"),
        "local_time": tz.get("local_time") or first("local_time"),
        "is_dst": tz.get("is_dst") if tz else first("is_dst"),
        "anonymity": anonymity,
        "anonymity_detail": anonymity_detail,
        "rdap": rdap,
        "confidence": {
            "level": level,
            "note": note,
            "sources_responded": total,
            "agreement": f"{len(pool)}/{total}",
            "coordinate_spread_km": round(spread, 1) if all_coords else None,
            "pinpoint": "city-level estimate from provider consensus"
            if level in ("high", "medium") else "low-confidence estimate",
        },
        "sources": [
            {
                "name": r.get("source"),
                "city": r.get("city"),
                "region": r.get("region"),
                "country": r.get("country"),
                "latitude": r.get("latitude"),
                "longitude": r.get("longitude"),
            }
            for r in records
        ],
    }


async def tor_exit_nodes() -> set[str]:
    """The Tor Project's published bulk exit-node list."""
    try:
        text = await http.fetch_text("https://check.torproject.org/torbulkexitlist", ttl=3600)
    except Exception:
        return set()
    return {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")}


async def is_tor_exit(ip: str) -> bool:
    return ip in await tor_exit_nodes()


async def reverse_dns(ip: str) -> Optional[str]:
    """PTR lookup through Cloudflare's public DoH resolver."""
    if ":" in ip:
        rev = ".".join(reversed(ip.replace(":", ""))) + ".ip6.arpa"
    else:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    try:
        data = await http.fetch_json(
            "https://cloudflare-dns.com/dns-query",
            params={"name": rev, "type": "PTR"},
            headers={"accept": "application/dns-json"},
            ttl=900,
        )
    except Exception:
        return None
    for ans in (data or {}).get("Answer", []):
        if ans.get("type") == 12:
            return (ans.get("data") or "").rstrip(".")
    return None


async def rdap_ip(ip: str) -> dict:
    """Registration data for the IP's network block (RDAP)."""
    try:
        data = await http.fetch_json(f"https://rdap.org/ip/{ip}", ttl=86400)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    cidrs = []
    for block in data.get("cidr0_cidrs") or []:
        prefix = block.get("v4prefix") or block.get("v6prefix")
        length = block.get("length")
        if prefix:
            cidrs.append(f"{prefix}/{length}" if length is not None else prefix)
    entities = []
    for ent in data.get("entities") or []:
        roles = ", ".join(ent.get("roles") or [])
        vcard = ent.get("vcardArray") or [None, []]
        name = None
        for item in (vcard[1] if len(vcard) > 1 else []):
            if isinstance(item, list) and item and item[0] == "fn":
                name = item[3]
                break
        entities.append({"handle": ent.get("handle"), "roles": roles, "name": name})
    return {
        "source": "rdap.org",
        "name": data.get("name"),
        "handle": data.get("handle"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "type": data.get("type"),
        "country": data.get("country"),
        "cidrs": cidrs,
        "entities": entities[:8],
        "last_changed": data.get("lastChanged"),
    }


async def resolve_host(host: str) -> dict:
    """Resolve a hostname to A/AAAA records, then geolocate the primary IP."""
    out: dict[str, Any] = {"host": host, "addresses": []}
    loop = asyncio.get_running_loop()
    addrs: list[str] = []
    try:
        infos = await loop.getaddrinfo(host, None)
        addrs = sorted({info[4][0] for info in infos})
    except Exception as exc:
        out["resolve_error"] = str(exc)
    if not addrs:
        # System resolver may be restricted; fall back to DNS-over-HTTPS.
        addrs = await _doh_addresses(host)
    out["addresses"] = addrs
    if not addrs:
        out.setdefault("error", f"DNS resolution failed: {out.get('resolve_error', 'no records')}")
        return out
    # Prefer IPv4 for geolocation: providers have the best coverage there.
    primary = next((a for a in addrs if ":" not in a), addrs[0])
    out["primary_ip"] = primary
    out["geo"] = await lookup_ip(primary)
    return out


async def _doh_addresses(host: str) -> list[str]:
    """Resolve A/AAAA records over DNS-over-HTTPS as a fallback."""
    addrs: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            data = await http.fetch_json(
                _DOH,
                params={"name": host, "type": rtype},
                headers=_DOH_HEADERS,
                ttl=300,
            )
        except Exception:
            continue
        for ans in data.get("Answer", []) if isinstance(data, dict) else []:
            if ans.get("type") in (1, 28) and ans.get("data"):
                addrs.append(ans["data"])
    return sorted(set(addrs))


def local_time(tz_id: Optional[str]) -> dict:
    """Current wall-clock time in the given IANA timezone."""
    if not tz_id:
        return {}
    try:
        from datetime import datetime
        from zoneinfo import ZoneInfo

        now = datetime.now(ZoneInfo(tz_id))
        offset = now.utcoffset()
        offset_hours = offset.total_seconds() / 3600 if offset else 0
        return {
            "timezone": tz_id,
            "local_time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "utc_offset": f"UTC{offset_hours:+g}",
            "is_dst": bool(now.dst()),
        }
    except Exception:
        return {"timezone": tz_id}
