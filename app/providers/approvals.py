"""ERC-20 / NFT approval (allowance) intelligence.

An approval is a standing permission a wallet grants to a spender to move its
tokens without further confirmation. Forgotten or unlimited approvals are one
of the most common ways funds are drained: the spender contract keeps working
long after the user stopped thinking about it.

How this is built, and its honest limits:

* Approvals are *events*, not current state, so the only reliable way to report
  the live risk is to (a) find the approval calls a wallet made and (b) re-read
  the *current* allowance for each (token, spender) pair with an ``eth_call``.
  This module does both. A revoked approval therefore does not appear, which is
  the whole point.
* Finding every historical approval would require indexing the chain. Free
  public RPCs refuse wide ``eth_getLogs`` ranges, so approvals are read from the
  wallet's recent transaction history. The scanned window is reported and the
  coverage limitation is stated plainly; older approvals outside the window are
  not covered.
* A spender is only flagged when it matches a curated label or the sanctions
  list. Everything else is listed as unlabelled, never guessed.
"""
from __future__ import annotations

import asyncio
from typing import Optional

from .. import labels
from . import evm, http

# Function selectors (first 4 bytes of keccak of the signature).
SEL_APPROVE = "095ea7b3"  # approve(address,uint256)
SEL_INCREASE = "39509351"  # increaseAllowance(address,uint256)
SEL_SET_FOR_ALL = "a22cb465"  # setApprovalForAll(address,bool)
SEL_ALLOWANCE = "dd62ed3e"  # allowance(address,address)
SEL_IS_APPROVED_FOR_ALL = "e985e9c5"  # isApprovedForAll(address,address)

_APPROVAL_SELECTORS = {SEL_APPROVE, SEL_INCREASE, SEL_SET_FOR_ALL}

# Anything at or above 2**255 is treated as "unlimited" in practice.
_UNLIMITED = 2**255

_PAGES = 3  # transaction pages scanned (50 rows each in the v2 API)
_MIN_WINDOW = 100  # widen the scan if the analyzer handed over fewer rows


def _decode_address(word: str) -> Optional[str]:
    word = word.strip()
    if len(word) != 64:
        return None
    return "0x" + word[24:].lower()


def _parse_approval_input(to: str, data: str) -> Optional[dict]:
    """Decode an approval call into {spender, unlimited, nft}."""
    if not data or not data.startswith("0x"):
        return None
    body = data[2:]
    selector = body[:8].lower()
    if selector not in _APPROVAL_SELECTORS:
        return None
    args = body[8:]
    if len(args) < 64:
        return None
    spender = _decode_address(args[:64])
    if not spender:
        return None
    if selector == SEL_SET_FOR_ALL:
        raw = args[64:128]
        approved = raw[-1] == "1" if raw else False
        return {"spender": spender, "nft": True, "unlimited": bool(approved), "revoked": not approved}
    amount_hex = args[64:128]
    try:
        amount = int(amount_hex, 16)
    except Exception:
        amount = 0
    return {"spender": spender, "nft": False, "unlimited": amount >= _UNLIMITED, "revoked": amount == 0}


async def _txlist_page(address: str, params: Optional[dict] = None) -> dict:
    """One page of the address's transactions from the Blockscout v2 API.

    The v2 endpoint is throttled far more gently than the legacy v1 one, which
    matters because this scan adds several requests to every wallet report.
    """
    query = dict(params or {})
    try:
        data = await http.fetch_json(
            f"https://eth.blockscout.com/api/v2/addresses/{address}/transactions",
            params=query or None,
            ttl=300,
        )
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _normalize_tx(tx: dict) -> dict:
    """Flatten a Blockscout v2 transaction into the shape the scanner uses."""
    frm = tx.get("from")
    to = tx.get("to")
    return {
        "from": (frm or {}).get("hash") if isinstance(frm, dict) else frm,
        "to": (to or {}).get("hash") if isinstance(to, dict) else to,
        "raw_input": tx.get("raw_input") or tx.get("input"),
        "hash": tx.get("hash"),
        "block_number": tx.get("block_number"),
        "timestamp": tx.get("timestamp"),
    }


async def _current_allowance(owner: str, token: str, spender: str, *, nft: bool) -> Optional[int]:
    """Read the live allowance / isApprovedForAll value."""
    selector = SEL_IS_APPROVED_FOR_ALL if nft else SEL_ALLOWANCE
    data = selector + owner[2:].rjust(64, "0") + spender[2:].rjust(64, "0")
    out = await evm.eth_call(token, "0x" + data)
    if not out or not out.startswith("0x") or len(out) < 3:
        return None
    try:
        return int(out, 16)
    except Exception:
        return None


async def scan(
    address: str,
    *,
    transactions: Optional[list] = None,
    max_checks: int = 24,
) -> dict:
    """Find approvals in the wallet's recent history and verify their live state.

    ``transactions`` is the normal-transaction list the analyzer already
    fetched; when supplied it is reused so this scan adds no provider calls.
    """
    addr = address.lower()

    rows = [tx for tx in (transactions or []) if isinstance(tx, dict)]
    if len(rows) < _MIN_WINDOW:
        # Widen the window beyond what the analyzer fetched: follow the v2
        # cursor for a few pages. The endpoint is cached, so this is cheap.
        params: Optional[dict] = None
        for _ in range(_PAGES):
            data = await _txlist_page(addr, params)
            items = data.get("items") or []
            rows.extend(_normalize_tx(tx) for tx in items if isinstance(tx, dict))
            params = data.get("next_page_params")
            if not params:
                break
    if not rows:
        return {
            "available": False,
            "reason": "transaction history unavailable; approvals could not be read",
        }

    # Collect the distinct (token, spender, nft) approvals seen in the window.
    seen: dict[tuple, dict] = {}
    scanned = 0
    for tx in rows:
        frm = (tx.get("from") or "").lower()
        if frm != addr:
            continue
        data = tx.get("input") or tx.get("raw_input") or ""
        parsed = _parse_approval_input(tx.get("to") or "", data)
        if not parsed:
            continue
        token = (tx.get("to") or "").lower()
        key = (token, parsed["spender"], parsed["nft"])
        entry = seen.setdefault(
            key,
            {
                "token": token,
                "spender": parsed["spender"],
                "nft": parsed["nft"],
                "last_seen": tx.get("timeStamp") or tx.get("timestamp"),
                "txid": tx.get("hash"),
                "call_unlimited": parsed["unlimited"],
                "call_revoked": parsed.get("revoked", False),
            },
        )
        scanned += 1

    # Verify the live state of each distinct approval.
    keys = list(seen.keys())[:max_checks]
    live = await asyncio.gather(
        *[_current_allowance(addr, k[0], k[1], nft=k[2]) for k in keys],
        return_exceptions=False,
    )

    active: list[dict] = []
    for key, value in zip(keys, live):
        entry = seen[key]
        if value is None:
            entry["live_state"] = "unknown"
            active.append(entry)
            continue
        if value == 0:
            continue  # revoked since the call; do not report as a live risk
        entry["live_state"] = "active"
        entry["unlimited"] = (value >= _UNLIMITED) if not entry["nft"] else bool(value)
        entry["allowance_raw"] = str(value)
        active.append(entry)

    # Attribute spenders: curated labels first, then the explorer's own
    # contract name, then an OFAC screen. A spender's *identity* is the single
    # most useful thing about an approval, so it is worth a lookup each -- but
    # dedupe by spender/token and fetch concurrently, or a wallet with dozens
    # of approvals turns into dozens of serial requests.
    from ..providers import blockscout, sanctions

    label_map: dict[str, dict] = {}
    meta_map: dict[str, dict] = {}
    unique_spenders = {e["spender"] for e in active}
    unique_tokens = {e["token"] for e in active}

    async def _spender_meta(spender: str) -> tuple[str, dict]:
        lab = labels.label_eth(spender)
        if lab:
            return spender, lab
        info = await blockscout.address_info(spender)
        name = (info or {}).get("contract_name")
        if name:
            return spender, {"name": name, "category": "contract"}
        if info and info.get("is_contract") is False:
            return spender, {"category": "eoa"}
        return spender, {}

    spenders_meta = await asyncio.gather(*[_spender_meta(s) for s in unique_spenders])
    label_map = dict(spenders_meta)

    tokens_meta = await asyncio.gather(*[blockscout.token_info(t) for t in unique_tokens])
    meta_map = dict(zip(unique_tokens, tokens_meta))

    findings = []
    for entry in active:
        lab = label_map.get(entry["spender"]) or {}
        entry["spender_label"] = lab.get("name")
        entry["spender_category"] = lab.get("category")
        if lab.get("jurisdiction"):
            entry["spender_jurisdiction"] = lab["jurisdiction"]
        meta = meta_map.get(entry["token"]) or {}
        if meta.get("symbol"):
            entry["token_label"] = meta["symbol"] + (f" · {meta['name']}" if meta.get("name") else "")
            entry["token_type"] = meta.get("type")
        hit = await sanctions.screen("ETH", entry["spender"])
        if hit.get("listed"):
            entry["sanctioned"] = True
        if entry.get("unlimited") or entry.get("sanctioned") or lab.get("category") == "mixer":
            findings.append(
                {
                    "severity": "high" if entry.get("sanctioned") or lab.get("category") == "mixer" else "medium",
                    "detail": _finding_text(entry),
                }
            )

    return {
        "available": True,
        "scanned_transactions": len(rows),
        "approval_calls_seen": scanned,
        "distinct_approvals": len(seen),
        "checked": len(keys),
        "active": active,
        "active_count": len(active),
        "unlimited_count": sum(1 for a in active if a.get("unlimited")),
        "flagged": [a for a in active if a.get("unlimited") or a.get("sanctioned")],
        "findings": findings,
        "coverage": (
            f"Approvals are read from the most recent {len(rows)} transactions and then re-verified "
            "against current on-chain state. Older approvals outside this window are not covered."
        ),
    }


def _finding_text(entry: dict) -> str:
    who = entry.get("spender_label") or entry["spender"][:10] + "…"
    kind = "NFT operator approval" if entry.get("nft") else "token allowance"
    if entry.get("sanctioned"):
        return f"Active {kind} to a sanctioned address ({who})"
    if entry.get("spender_category") == "mixer":
        return f"Active {kind} to a mixer contract ({who})"
    if entry.get("unlimited"):
        return f"Unlimited {kind} to {who}"
    return f"Active {kind} to {who}"
