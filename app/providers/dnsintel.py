"""Hostname and domain intelligence.

DNS records come from Cloudflare's and Google's public DNS-over-HTTPS
resolvers (queried in parallel for cross-checking). Domain registration comes
from RDAP and certificate transparency subdomains from crt.sh.
"""
from __future__ import annotations

import asyncio

from . import http

_DOH = "https://cloudflare-dns.com/dns-query"
_DOH_HEADERS = {"accept": "application/dns-json"}
_TYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 257: "CAA",
}

async def _doh(name: str, rtype: str) -> list[dict]:
    try:
        data = await http.fetch_json(
            _DOH,
            params={"name": name, "type": rtype},
            headers=_DOH_HEADERS,
            ttl=600,
        )
    except Exception:
        return []
    out = []
    for ans in (data or {}).get("Answer", []):
        out.append(
            {
                "name": (ans.get("name") or "").rstrip("."),
                "type": _TYPE_NAMES.get(ans.get("type"), str(ans.get("type"))),
                "value": (ans.get("data") or "").strip('"'),
                "ttl": ans.get("TTL"),
            }
        )
    return out
async def dns_records(host: str) -> dict:
    """Fetch the common record types for a host in parallel."""
    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
    results = await asyncio.gather(*[_doh(host, t) for t in types])
    records: dict[str, list[dict]] = {}
    for rtype, rows in zip(types, results):
        if rows:
            records[rtype] = rows
    return {"host": host, "records": records}
async def rdap_domain(domain: str) -> dict:
    """Domain registration details via RDAP."""
    try:
        data = await http.fetch_json(f"https://rdap.org/domain/{domain}", ttl=86400)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    events = {}
    for ev in data.get("events") or []:
        action = ev.get("eventAction")
        if action:
            events[action] = ev.get("eventDate")
    entities = []
    for ent in data.get("entities") or []:
        roles = ", ".join(ent.get("roles") or [])
        vcard = ent.get("vcardArray") or [None, []]
        fields: dict[str, str] = {}
        for item in (vcard[1] if len(vcard) > 1 else []):
            if isinstance(item, list) and len(item) >= 4:
                key = item[0]
                val = item[3]
                if isinstance(val, list):
                    val = " ".join(str(x) for x in val if isinstance(x, str))
                fields[key] = str(val)
        entities.append(
            {
                "handle": ent.get("handle"),
                "roles": roles,
                "name": fields.get("fn"),
                "org": fields.get("org"),
                "email": fields.get("email"),
            }
        )
    nameservers = [ns.get("ldhName", "").lower() for ns in data.get("nameservers") or []]
    status = data.get("status") or []
    return {
        "source": "rdap.org",
        "domain": (data.get("ldhName") or domain).lower(),
        "handle": data.get("handle"),
        "registrar": next((e["name"] or e["org"] for e in entities if "registrar" in e["roles"]), None),
        "status": status,
        "nameservers": [n for n in nameservers if n],
        "created": events.get("registration"),
        "updated": events.get("last changed"),
        "expires": events.get("expiration"),
        "entities": entities[:6],
        "dnssec": bool(data.get("secureDNS", {}).get("delegationSigned")),
    }
async def subdomains(domain: str, limit: int = 60) -> dict:
    """Certificate-transparency subdomains via crt.sh."""
    try:
        rows = await http.fetch_json(
            "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, ttl=86400
        )
    except Exception:
        return {"count": 0, "names": []}
    names: set[str] = set()
    issuers: set[str] = set()
    for row in rows or []:
        for name in (row.get("name_value") or "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name and name.endswith(domain):
                names.add(name)
        if row.get("issuer_name"):
            issuers.add(row["issuer_name"])
    return {
        "count": len(names),
        "names": sorted(names)[:limit],
        "issuers": sorted(issuers)[:8],
    }
