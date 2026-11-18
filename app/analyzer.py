"""Analysis orchestration.

Turns a raw search target (address, ENS name, IP or hostname) into a single
normalized intelligence report by fanning out to the provider clients and
reducing their responses into identity, balances, portfolio, activity,
counterparties, timeline and risk sections.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional

from . import clustering, config, detect, fundflow, labels, txorigin
from .providers import (
    approvals,
    attribution,
    blockscout,
    dnsintel,
    dogechain,
    ens,
    esplora,
    evm,
    geo,
    goplus,
    linkedfootprint,
    multichain,
    prices,
    sanctions,
    solana,
    tron,
    xrp,
)

SATOSHI = 1e8


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _iso(ts: Optional[float]) -> Optional[str]:
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except Exception:
        return None


def _risk_level(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 10:
        return "medium"
    return "low"


def _price_source(price_table: dict) -> str:
    """Report which upstream supplied the native price."""
    sources = {
        entry.get("source")
        for entry in (price_table or {}).values()
        if isinstance(entry, dict) and entry.get("source")
    }
    if not sources:
        return "unavailable"
    return " + ".join(sorted(sources))


def _value_tokens(tokens: list, price_map: dict, key_field: str) -> list:
    """Attach USD values to a token list."""
    out = []
    for tok in tokens:
        key = (tok.get(key_field) or "").lower()
        price = price_map.get(key) or {}
        amount = tok.get("amount") or 0
        usd = (price.get("usd") or 0) * amount if price.get("usd") else None
        tok = {**tok, "price_usd": price.get("usd"), "change_24h": price.get("change_24h"), "value_usd": usd}
        out.append(tok)
    out.sort(key=lambda t: (t.get("value_usd") or 0), reverse=True)
    return out


# --------------------------------------------------------------------------- #
# Ethereum
# --------------------------------------------------------------------------- #
async def _analyze_eth(
    address: str,
    target: detect.Target,
    *,
    website: Optional[str] = None,
    ens_name: Optional[str] = None,
) -> dict:
    addr = address.lower()
    report: dict[str, Any] = {"target": {"input": target.raw, "chain": "ETH", "address": addr}}
    errors: list[str] = []
    providers: list[str] = []

    core, eth_info, txs, history, goplus_res, ofac, reverse, bs_info, bs_counters, bs_nfts, bs_txs, bs_tokens = await asyncio.gather(
        evm.get_core(addr),
        _safe(evm.ethplorer_address(addr)),
        _safe(evm.ethplorer_transactions(addr, 40), default=[]),
        _safe(evm.ethplorer_history(addr, 60), default=[]),
        _safe(goplus.address_security(addr)),
        _safe(sanctions.screen("ETH", addr)),
        _safe(ens.reverse(addr)),
        _safe(blockscout.address_info(addr)),
        _safe(blockscout.counters(addr)),
        _safe(blockscout.nfts(addr)),
        _safe(blockscout.transactions(addr, limit=40), default=[]),
        _safe(blockscout.token_balances(addr), default=[]),
        return_exceptions=False,
    )
    providers += ["Ethereum JSON-RPC", "Ethplorer", "Blockscout", "GoPlus Labs", "OFAC SDN"]

    bs_transfers = await _safe(blockscout.token_transfers(addr, limit=40), default=[])

    contract_meta = {}
    if core.get("is_contract"):
        contract_meta = await _safe(blockscout.contract_info(addr), default={})

    native_price = await _safe(prices.native_prices(["ETH"]), default={})
    eth_usd = (native_price.get("ETH") or {}).get("usd")

    # --- identity ---
    identity: dict[str, Any] = {"chain": "ETH", "address": addr}
    if reverse and reverse.get("resolved"):
        identity["ens"] = reverse.get("name")
        identity["ens_profile"] = {
            k: reverse.get(k)
            for k in ("avatar", "description", "url", "twitter", "github", "email", "discord", "telegram")
            if reverse.get(k)
        }
    label = labels.label_eth(addr)
    if label:
        identity["label"] = label
    # Blockscout's public tags and contract metadata enrich identity.
    if bs_info.get("contract_name"):
        identity["contract_name"] = bs_info["contract_name"]
    if bs_info.get("public_tags"):
        identity["public_tags"] = bs_info["public_tags"]
    if bs_info.get("creator"):
        identity["creator"] = bs_info["creator"]
    if bs_info.get("creation_tx"):
        identity["creation_tx"] = bs_info["creation_tx"]
    if bs_info.get("implementation"):
        identity["implementation"] = bs_info["implementation"]
    if core.get("is_contract"):
        identity["type"] = "contract"
        identity["bytecode_size"] = core.get("bytecode_size")
        contract = (eth_info or {}).get("contractInfo") or {}
        if contract:
            identity["contract"] = {
                "name": contract.get("name"),
                "symbol": contract.get("symbol"),
                "decimals": contract.get("decimals"),
                "total_supply": contract.get("totalSupply"),
            }
        if contract_meta:
            identity["verified_contract"] = {
                "verified": contract_meta.get("verified"),
                "name": contract_meta.get("name"),
                "compiler": contract_meta.get("compiler"),
                "language": contract_meta.get("language"),
                "license": contract_meta.get("license"),
                "proxy_type": contract_meta.get("proxy_type"),
                "implementations": contract_meta.get("implementations"),
            }
    elif core.get("is_delegated_eoa"):
        identity["type"] = "externally-owned account (EIP-7702 delegated)"
        identity["delegate_address"] = core.get("delegate_address")
    else:
        identity["type"] = "externally-owned account (EOA)"

    # --- balances ---
    native_balance = _known_balance(core)
    if native_balance is None:
        errors.append(
            "Balance could not be read: no EVM RPC endpoint answered. The wallet's "
            "holdings are unknown for this run, not zero."
        )
    tokens_raw = []
    if bs_tokens:
        # Blockscout returns every ERC-20 balance with logos and its own price
        # feed; prefer it and keep the largest positions.
        for tok in bs_tokens:
            tokens_raw.append(
                {
                    "contract": (tok.get("contract") or "").lower(),
                    "name": tok.get("name"),
                    "symbol": tok.get("symbol"),
                    "decimals": tok.get("decimals") or 18,
                    "amount": tok.get("amount") or 0,
                    "logo": tok.get("icon"),
                    "holders": tok.get("holders"),
                    "bs_price_usd": tok.get("price_usd"),
                }
            )
    else:
        for tok in (eth_info or {}).get("tokens") or []:
            info = tok.get("tokenInfo") or {}
            try:
                decimals = int(info.get("decimals") or 18)
            except Exception:
                decimals = 18
            try:
                raw = int(tok.get("rawBalance") or 0)
            except Exception:
                raw = 0
            tokens_raw.append(
                {
                    "contract": (info.get("address") or "").lower(),
                    "name": info.get("name"),
                    "symbol": info.get("symbol"),
                    "decimals": decimals,
                    "amount": raw / (10 ** decimals) if decimals else raw,
                    "bs_price_usd": (info.get("price") or {}).get("rate"),
                }
            )

    # Price lookups are per-contract, so rank by the explorer's own valuation
    # and only price the largest positions. The tail is counted separately so
    # the portfolio total stays honest without thousands of upstream calls.
    for t in tokens_raw:
        t["_rank"] = (t.get("bs_price_usd") or 0) * (t.get("amount") or 0)
    tokens_raw.sort(key=lambda t: t["_rank"], reverse=True)
    token_count = len(tokens_raw)
    head = tokens_raw[:150]
    tail = tokens_raw[150:]

    price_map = await _safe(
        prices.token_price_eth([t["contract"] for t in head if t.get("contract")]),
        default={},
    )
    # Fall back to the explorer's own price when CoinGecko has no listing.
    for t in head + tail:
        if not price_map.get((t.get("contract") or "").lower(), {}).get("usd") and t.get("bs_price_usd"):
            price_map[(t.get("contract") or "").lower()] = {"usd": t["bs_price_usd"], "change_24h": None}
    tokens = _value_tokens(head, price_map, "contract")
    tail_value = sum(
        (price_map.get((t.get("contract") or "").lower(), {}).get("usd") or 0) * (t.get("amount") or 0)
        for t in tail
    )

    native_usd = (native_balance * eth_usd) if (native_balance is not None and eth_usd) else None
    token_total_usd = sum(t.get("value_usd") or 0 for t in tokens) + tail_value
    total_usd = (native_usd or 0) + token_total_usd

    report["balances"] = {
        "native": {
            "symbol": "ETH",
            "amount": native_balance,
            "price_usd": eth_usd,
            "value_usd": native_usd,
        },
        "tokens": tokens,
        "token_count": token_count,
        "tokens_shown": len(tokens),
    }
    report["portfolio"] = {
        "total_value_usd": total_usd if (native_usd is not None or token_total_usd) else None,
        "native_value_usd": native_usd,
        "token_value_usd": token_total_usd,
        "price_source": _price_source(native_price),
    }
    if bs_nfts and bs_nfts.get("count"):
        report["nfts"] = bs_nfts

    # --- activity ---
    timestamps = [t.get("timestamp") for t in txs if t.get("timestamp")]
    activity = {
        "outgoing_tx_count": core.get("outgoing_tx_count"),
        "nonce": core.get("nonce"),
        "recent_tx_sample": len(txs),
        "first_activity": _iso(min(timestamps)) if timestamps else None,
        "last_activity": _iso(max(timestamps)) if timestamps else None,
    }
    if bs_counters:
        activity["lifetime_transactions"] = bs_counters.get("transactions")
        activity["lifetime_token_transfers"] = bs_counters.get("token_transfers")
        activity["gas_used"] = bs_counters.get("gas_usage")
    if bs_info.get("token_holder_count") is not None:
        activity["tokens_held"] = bs_info.get("token_holder_count")
    report["activity"] = activity

    # --- exposure (what the wallet actually touches) ---
    exposure = {
        "erc20_positions": token_count,
        "nft_collections": (bs_nfts or {}).get("count", 0),
        "has_contract_interactions": bool(bs_info.get("has_logs")),
    }
    # Flag the riskiest held tokens using GoPlus token security, best effort.
    risky_tokens = []
    top_for_check = [t for t in tokens[:12] if t.get("contract")]
    if top_for_check:
        checks = await asyncio.gather(
            *[_safe(goplus.token_security("1", t["contract"])) for t in top_for_check],
            return_exceptions=False,
        )
        for tok, chk in zip(top_for_check, checks):
            if chk and chk.get("flags"):
                risky_tokens.append(
                    {
                        "symbol": tok.get("symbol"),
                        "contract": tok.get("contract"),
                        "flags": chk["flags"],
                        "is_honeypot": chk.get("is_honeypot"),
                        "buy_tax": chk.get("buy_tax"),
                        "sell_tax": chk.get("sell_tax"),
                    }
                )
    if risky_tokens:
        exposure["flagged_tokens"] = risky_tokens
    report["exposure"] = exposure

    # --- counterparties + timeline ---
    counterparties: dict[str, dict] = {}
    timeline: list[dict] = []
    for tx in txs:
        frm = (tx.get("from") or "").lower()
        to = (tx.get("to") or "").lower()
        ts = tx.get("timestamp")
        value = tx.get("value") or 0
        direction = "in" if to == addr else "out"
        other = frm if direction == "in" else to
        if other and other != addr:
            entry = counterparties.setdefault(other, {"address": other, "tx_count": 0, "value": 0.0, "direction": {"in": 0, "out": 0}})
            entry["tx_count"] += 1
            entry["value"] += value
            entry["direction"][direction] += 1
            lab = labels.label_eth(other)
            if lab:
                entry["label"] = lab["name"]
                entry["label_category"] = lab["category"]
                if lab.get("jurisdiction"):
                    entry["jurisdiction"] = lab["jurisdiction"]
        timeline.append(
            {
                "timestamp": _iso(ts),
                "type": "native_transfer",
                "direction": direction,
                "counterparty": other,
                "value": value,
                "symbol": "ETH",
                "value_usd": (value * eth_usd) if eth_usd else tx.get("usdValue"),
                "txid": tx.get("hash"),
                "success": tx.get("success"),
            }
        )

    # enrich with token-transfer history
    for ev in history:
        if not isinstance(ev, dict):
            continue
        if ev.get("type") not in (None, "transfer"):
            continue
        tok = ev.get("tokenInfo") or {}
        if not isinstance(tok, dict):
            tok = {}
        ts = ev.get("timestamp")
        try:
            decimals = int(tok.get("decimals") or 18)
        except Exception:
            decimals = 18
        amount = int(ev.get("value") or 0) / (10 ** decimals) if decimals else 0
        frm = (ev.get("from") or "").lower()
        to = (ev.get("to") or "").lower()
        direction = "in" if to == addr else "out"
        other = frm if direction == "in" else to
        timeline.append(
            {
                "timestamp": _iso(ts),
                "type": "token_transfer",
                "direction": direction,
                "counterparty": other,
                "value": amount,
                "symbol": tok.get("symbol"),
                "token": tok.get("name"),
                "txid": ev.get("hash") or ev.get("transactionHash"),
            }
        )
        if other and other != addr:
            entry = counterparties.setdefault(other, {"address": other, "tx_count": 0, "value": 0.0, "direction": {"in": 0, "out": 0}})
            entry["tx_count"] += 1
            entry["direction"][direction] += 1

    timeline.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
    top_counterparties = sorted(counterparties.values(), key=lambda c: c["tx_count"], reverse=True)[:25]
    report["counterparties"] = top_counterparties
    report["timeline"] = timeline[:60]

    # --- approvals (standing token permissions) ---
    appr = await _safe(
        approvals.scan(addr, transactions=bs_txs or []),
        default=None,
    )
    if appr and appr.get("available"):
        report["approvals"] = appr
        if appr.get("active_count"):
            exposure["active_approvals"] = appr["active_count"]
            exposure["unlimited_approvals"] = appr.get("unlimited_count", 0)

    # --- clustering (related-address and behaviour patterns) ---
    cluster = clustering.analyze(bs_txs or [], addr)
    if cluster and cluster.get("signals"):
        report["clustering"] = cluster

    # --- fund-flow tracing (ego network + taint exposure) ---
    # This is the investigator's core question: who does this address deal with,
    # and does any of that flow pass through a sanctioned or high-risk entity?
    ego = fundflow.build_ego_network(addr, transactions=bs_txs or [], token_transfers=bs_transfers or [])
    if ego.get("counterparty_count"):
        report["ego_network"] = ego

        ofac_set = await _safe(sanctions.address_set("ETH"), default=set())
        # Screen the largest counterparties with GoPlus in parallel; only the
        # head matters, and each call is cached.
        head_addrs = [n["address"] for n in ego["nodes"][:8]]
        gp_results = await asyncio.gather(
            *(_safe(goplus.address_security(a), default={}) for a in head_addrs)
        )
        goplus_by_addr = {a: r for a, r in zip(head_addrs, gp_results) if r}

        indirect = await _safe(
            fundflow.second_hop(
                ego,
                fetch_transactions=lambda a: blockscout.transactions(a, limit=15),
                sanctions_hits=ofac_set,
                labels_lookup=lambda a: (labels.label_eth(a) or {}).get("name"),
            ),
            default=[],
        )

        taint = fundflow.assess_taint(
            addr,
            ego,
            sanctions_hits=ofac_set,
            goplus_by_addr=goplus_by_addr,
            indirect=indirect,
        )
        report["taint"] = taint
        if taint.get("worst_severity") in ("critical", "high"):
            exposure["taint_severity"] = taint["worst_severity"]
            exposure["taint_exposures"] = taint.get("exposure_count")
        providers.append("Fund-flow tracing (OFAC + GoPlus + labels)")

    # --- entity attribution (who is this address) ---
    # Prefer the richest explorer party object available (token transfers carry
    # the fullest label set), else fall back to a transaction party.
    party = None
    for tr in bs_transfers or []:
        for candidate in (tr.get("from_party"), tr.get("to_party")):
            if isinstance(candidate, dict) and (candidate.get("hash") or "").lower() == addr:
                party = candidate
                break
        if party:
            break
    if not party:
        for tx in bs_txs or []:
            if (tx.get("to") or "").lower() == addr or (tx.get("from") or "").lower() == addr:
                party = {"name": None}
                break
    dossier = attribution.attribute(
        addr,
        chain="ETH",
        explorer_party=party,
        reverse_ens=reverse if (reverse and reverse.get("resolved")) else None,
        goplus=goplus_res,
        ofac=ofac,
        is_contract=bool(core.get("is_contract")),
        counterparty_count=ego.get("counterparty_count", 0),
    )
    if dossier.get("claim_count"):
        report["attribution"] = dossier
        providers.append("Entity attribution (explorer labels + ENS + curated)")

    # --- cross-chain presence (same address, every EVM chain) ---
    # A 0x address is valid on every EVM chain; an explorer shows only one. This
    # answers "where does this address actually hold value" in one pass.
    mc = await _safe(
        multichain.sweep(
            addr,
            native_prices={
                "ETH": eth_usd,
                "POL": (native_price.get("POL") or {}).get("usd"),
                "XDAI": (native_price.get("XDAI") or {}).get("usd"),
            },
        ),
        default=None,
    )
    if mc and mc.get("chains_active", 0) > 1:
        report["multichain"] = mc
        providers.append("Cross-chain sweep (8 EVM chains)")

    # --- linked footprint (the wallet's published website, if any) ---
    published_site = website or (identity.get("ens_profile") or {}).get("url")
    if published_site:
        footprint = await _safe(
            linkedfootprint.investigate(published_site, ens_name=ens_name), default=None
        )
        if footprint:
            report["linked_footprint"] = footprint
            providers.append("Linked website (DNS + IP geolocation)")

    # --- risk ---
    risk = _score_risk(
        goplus_flags=(goplus_res or {}).get("flags", []),
        ofac=ofac,
        is_contract=bool(core.get("is_contract")),
        is_new=(len(txs) < 3),
    )
    report["risk"] = risk
    report["identity"] = identity
    report["providers"] = providers
    report["errors"] = errors
    report["summary"] = _summary(report)
    return report


# --------------------------------------------------------------------------- #
# Bitcoin / Litecoin (Esplora)
# --------------------------------------------------------------------------- #
async def _analyze_esplora(chain: str, address: str, target: detect.Target) -> dict:
    report: dict[str, Any] = {"target": {"input": target.raw, "chain": chain, "address": address}}
    ofac_chain = "BTC" if chain == "BTC" else "LTC"

    info, txs, tip, ofac = await asyncio.gather(
        _safe(esplora.get_address(chain, address), default={}),
        _safe(esplora.get_transactions(chain, address, 30), default=[]),
        _safe(esplora.tip_height(chain)),
        _safe(sanctions.screen(ofac_chain, address)),
    )
    errors: list[str] = []
    if not info:
        errors.append(
            f"The {chain} explorer did not recognise this address. It may be malformed or not exist on this chain."
        )
    native_price = await _safe(prices.native_prices([chain]), default={})
    price_usd = (native_price.get(chain) or {}).get("usd")

    balance_native = _known_balance(info)
    if balance_native is None:
        errors.append(
            f"Balance could not be read from the {chain} explorer. Holdings are unknown "
            "for this run, not zero."
        )
    identity = {"chain": chain, "address": address, "type": "address"}

    report["balances"] = {
        "native": {
            "symbol": chain,
            "amount": balance_native,
            "price_usd": price_usd,
            "value_usd": (balance_native * price_usd) if (balance_native is not None and price_usd) else None,
        },
        "unconfirmed": info.get("unconfirmed_native"),
        "tokens": [],
        "token_count": 0,
    }
    report["portfolio"] = {
        "total_value_usd": (balance_native * price_usd) if (balance_native is not None and price_usd) else None,
        "native_value_usd": (balance_native * price_usd) if (balance_native is not None and price_usd) else None,
        "token_value_usd": 0,
        "price_source": _price_source(native_price),
    }

    counterparties: dict[str, dict] = {}
    timeline: list[dict] = []
    for tx in txs:
        txid = tx.get("txid")
        status = tx.get("status") or {}
        ts = status.get("block_time")
        incoming = 0
        outgoing = 0
        senders: dict[str, int] = {}
        receivers: dict[str, int] = {}
        for vin in tx.get("vin", []):
            prev = vin.get("prevout") or {}
            owner = prev.get("scriptpubkey_address")
            if not owner:
                continue
            if owner == address:
                outgoing += prev.get("value", 0)
            else:
                senders[owner] = senders.get(owner, 0) + prev.get("value", 0)
        for vout in tx.get("vout", []):
            owner = vout.get("scriptpubkey_address")
            if not owner:
                continue
            if owner == address:
                incoming += vout.get("value", 0)
            else:
                receivers[owner] = receivers.get(owner, 0) + vout.get("value", 0)

        net = incoming - outgoing
        direction = "in" if net >= 0 else "out"

        # The counterparty is the largest external party on the dominant side.
        pool = receivers if direction == "in" else senders
        counterparty = max(pool, key=pool.get) if pool else None
        for owner, val in {**senders, **receivers}.items():
            entry = counterparties.setdefault(
                owner, {"address": owner, "tx_count": 0, "value_sats": 0, "value": 0.0}
            )
            entry["tx_count"] += 1
            entry["value_sats"] += val
            entry["value"] += val / SATOSHI

        timeline.append(
            {
                "timestamp": _iso(ts),
                "type": "transaction",
                "direction": direction,
                "counterparty": counterparty,
                "value": abs(net) / SATOSHI,
                "symbol": chain,
                "value_usd": (abs(net) / SATOSHI * price_usd) if price_usd else None,
                "txid": txid,
                "confirmed": bool(status.get("confirmed")),
                "fee_sats": tx.get("fee"),
            }
        )

    timeline.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
    timestamps = [t for t in (e.get("timestamp") for e in timeline) if t]
    report["activity"] = {
        "tx_count": info.get("tx_count"),
        "funded_txo_count": info.get("funded_txo_count"),
        "spent_txo_count": info.get("spent_txo_count"),
        "received": info.get("received_sats", 0) / SATOSHI,
        "sent": info.get("sent_sats", 0) / SATOSHI,
        "mempool_tx_count": info.get("mempool_tx_count"),
        "first_activity": min(timestamps) if timestamps else None,
        "last_activity": max(timestamps) if timestamps else None,
        "chain_tip_height": tip,
    }
    report["counterparties"] = sorted(counterparties.values(), key=lambda c: c["tx_count"], reverse=True)[:25]
    report["timeline"] = timeline[:60]
    report["identity"] = identity
    report["risk"] = _score_risk(goplus_flags=[], ofac=ofac, is_contract=False, is_new=(info.get("tx_count", 0) < 3))
    report["providers"] = [f"{chain} Esplora explorer", "CoinGecko", "OFAC SDN"]
    report["errors"] = errors
    report["summary"] = _summary(report)
    return report


# --------------------------------------------------------------------------- #
# Dogecoin
# --------------------------------------------------------------------------- #
async def _analyze_doge(address: str, target: detect.Target) -> dict:
    report: dict[str, Any] = {"target": {"input": target.raw, "chain": "DOGE", "address": address}}
    balance, txs, ofac = await asyncio.gather(
        dogechain.get_balance(address),
        dogechain.get_transactions(address, 25),
        _safe(sanctions.screen("DOGE", address)),
    )
    native_price = await _safe(prices.native_prices(["DOGE"]), default={})
    price_usd = (native_price.get("DOGE") or {}).get("usd")
    bal = _known_balance(balance)
    errors: list[str] = []
    if bal is None:
        errors.append(
            "Balance could not be read from Dogechain. Holdings are unknown for this run, not zero."
        )

    report["balances"] = {
        "native": {"symbol": "DOGE", "amount": bal, "price_usd": price_usd,
                   "value_usd": (bal * price_usd) if (bal is not None and price_usd) else None},
        "unconfirmed": balance.get("unconfirmed_native"),
        "tokens": [],
        "token_count": 0,
    }
    report["portfolio"] = {
        "total_value_usd": (bal * price_usd) if (bal is not None and price_usd) else None,
        "native_value_usd": (bal * price_usd) if (bal is not None and price_usd) else None,
        "token_value_usd": 0,
        "price_source": _price_source(native_price),
    }

    timeline = []
    for tx in txs:
        ts = tx.get("time")
        val = float(tx.get("value") or 0)
        timeline.append(
            {
                "timestamp": _iso(ts),
                "type": "transaction",
                "direction": "unknown",
                "counterparty": None,
                "value": val,
                "symbol": "DOGE",
                "value_usd": (val * price_usd) if price_usd else None,
                "txid": tx.get("hash"),
                "block": tx.get("block"),
            }
        )
    timeline.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
    timestamps = [e["timestamp"] for e in timeline if e.get("timestamp")]
    report["activity"] = {
        "recent_tx_sample": len(txs),
        "first_activity": min(timestamps) if timestamps else None,
        "last_activity": max(timestamps) if timestamps else None,
    }
    report["counterparties"] = []
    report["timeline"] = timeline[:60]
    report["identity"] = {"chain": "DOGE", "address": address, "type": "address"}
    report["risk"] = _score_risk(goplus_flags=[], ofac=ofac, is_contract=False, is_new=(len(txs) < 3))
    report["providers"] = ["Dogechain.info", "CoinGecko", "OFAC SDN"]
    report["errors"] = errors
    report["summary"] = _summary(report)
    return report


# --------------------------------------------------------------------------- #
# Tron
# --------------------------------------------------------------------------- #
async def _analyze_tron(address: str, target: detect.Target) -> dict:
    report: dict[str, Any] = {"target": {"input": target.raw, "chain": "TRON", "address": address}}
    account, txs, trc20 = await asyncio.gather(
        tron.get_account(address),
        tron.get_transactions(address, 25),
        tron.get_trc20_transfers(address, 25),
    )
    native_price = await _safe(prices.native_prices(["TRX"]), default={})
    price_usd = (native_price.get("TRX") or {}).get("usd")
    bal = _known_balance(account)
    errors: list[str] = []
    if bal is None:
        errors.append(
            "Balance could not be read from TronGrid. Holdings are unknown for this run, not zero."
        )

    # TRC-20 token aggregation (Transfers only; Approvals carry no balance change)
    tokens: dict[str, dict] = {}
    for t in trc20:
        if t.get("type") != "Transfer":
            continue
        tok = t.get("token_info") or {}
        sym = tok.get("symbol") or "?"
        try:
            dec = int(tok.get("decimals") or 6)
        except Exception:
            dec = 6
        try:
            amount = int(t.get("value") or 0) / (10 ** dec)
        except (TypeError, ValueError):
            continue
        direction = "in" if t.get("to") == address else "out"
        entry = tokens.setdefault(sym, {"symbol": sym, "contract": tok.get("address"),
                                        "decimals": dec, "amount": 0.0, "name": tok.get("name")})
        entry["amount"] += amount if direction == "in" else -amount

    token_list = [t for t in tokens.values() if t["amount"] > 0]
    price_map = await _safe(
        prices.token_price_tron([t["contract"] for t in token_list if t.get("contract")]),
        default={},
    )
    token_total = 0.0
    for t in token_list:
        price = price_map.get(t.get("contract")) or {}
        usd = (price.get("usd") or 0) * t["amount"] if price.get("usd") else None
        t["price_usd"] = price.get("usd")
        t["change_24h"] = price.get("change_24h")
        t["value_usd"] = usd
        if usd:
            token_total += usd
    token_list.sort(key=lambda t: t.get("value_usd") or 0, reverse=True)

    native_usd = (bal * price_usd) if (bal is not None and price_usd) else None
    report["balances"] = {
        "native": {"symbol": "TRX", "amount": bal, "price_usd": price_usd,
                   "value_usd": native_usd},
        "frozen_native": account.get("frozen_native"),
        "tokens": token_list,
        "token_count": len(token_list),
        "exists": account.get("exists"),
    }
    report["portfolio"] = {
        "total_value_usd": (native_usd or 0) + token_total if (native_usd is not None or token_total) else None,
        "native_value_usd": native_usd,
        "token_value_usd": token_total,
        "price_source": _price_source(native_price),
    }

    timeline = []
    counterparties: dict[str, dict] = {}
    for tx in txs:
        raw = tx.get("raw_data") or {}
        contracts = raw.get("contract") or []
        ts = tx.get("block_timestamp")
        ts = ts / 1000 if ts else None
        ctype = None
        value = 0.0
        target_addr = None
        if contracts:
            c = contracts[0]
            ctype = c.get("type")
            val = c.get("parameter", {}).get("value", {})
            target_addr = val.get("to_address")
            amount = val.get("amount") or 0
            value = amount / 1e6 if ctype == "TransferContract" else 0
        direction = "in" if target_addr == address else "out"
        other = tx.get("raw_data", {}).get("contract", [{}])[0].get("parameter", {}).get("value", {}).get("owner_address") if direction == "in" else target_addr
        if other and other != address:
            e = counterparties.setdefault(other, {"address": other, "tx_count": 0})
            e["tx_count"] += 1
        timeline.append(
            {
                "timestamp": _iso(ts),
                "type": ctype or "contract",
                "direction": direction,
                "counterparty": other,
                "value": value,
                "symbol": "TRX",
                "value_usd": (value * price_usd) if price_usd else None,
                "txid": tx.get("txID"),
                "success": (tx.get("ret") or [{}])[0].get("contractRet"),
            }
        )
    for t in trc20:
        if t.get("type") != "Transfer":
            continue
        ts = (t.get("block_timestamp") or 0) / 1000 or None
        tok = t.get("token_info") or {}
        try:
            dec = int(tok.get("decimals") or 6)
        except Exception:
            dec = 6
        try:
            amount = int(t.get("value") or 0) / (10 ** dec)
        except (TypeError, ValueError):
            continue
        direction = "in" if t.get("to") == address else "out"
        timeline.append(
            {
                "timestamp": _iso(ts),
                "type": "trc20_transfer",
                "direction": direction,
                "counterparty": t.get("from") if direction == "in" else t.get("to"),
                "value": amount,
                "symbol": tok.get("symbol"),
                "token": tok.get("name"),
                "txid": t.get("transaction_id"),
            }
        )

    timeline.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
    timestamps = [e["timestamp"] for e in timeline if e.get("timestamp")]
    report["activity"] = {
        "recent_tx_sample": len(txs),
        "created_at": _iso((account.get("created_at") or 0) / 1000) if account.get("created_at") else None,
        "first_activity": min(timestamps) if timestamps else None,
        "last_activity": max(timestamps) if timestamps else None,
    }
    report["counterparties"] = sorted(counterparties.values(), key=lambda c: c["tx_count"], reverse=True)[:25]
    report["timeline"] = timeline[:60]
    report["identity"] = {
        "chain": "TRON",
        "address": address,
        "type": "contract" if account.get("is_contract") else "account",
    }
    report["risk"] = _score_risk(goplus_flags=[], ofac={"listed": False}, is_contract=bool(account.get("is_contract")), is_new=(len(txs) < 3))
    report["providers"] = ["TronGrid", "CoinGecko"]
    report["errors"] = errors
    report["summary"] = _summary(report)
    return report


# --------------------------------------------------------------------------- #
# Solana
# --------------------------------------------------------------------------- #
async def _analyze_solana(address: str, target: detect.Target) -> dict:
    report: dict[str, Any] = {"target": {"input": target.raw, "chain": "SOL", "address": address}}
    account, tokens, sigs = await asyncio.gather(
        solana.get_account(address),
        solana.get_tokens(address),
        solana.get_signatures(address, 25),
    )
    native_price = await _safe(prices.native_prices(["SOL"]), default={})
    price_usd = (native_price.get("SOL") or {}).get("usd")
    bal = _known_balance(account)
    sol_errors: list[str] = [account["error"]] if account.get("error") else []
    if bal is None and not sol_errors:
        sol_errors.append(
            "Balance could not be read from the Solana RPC. Holdings are unknown for this run, not zero."
        )

    price_map = await _safe(prices.token_price_solana([t["mint"] for t in tokens if t.get("mint")]), default={})
    priced_tokens = []
    token_total = 0.0
    for t in tokens:
        price = price_map.get(t.get("mint")) or {}
        amount = t.get("amount") or 0
        usd = (price.get("usd") or 0) * amount if price.get("usd") else None
        if usd:
            token_total += usd
        priced_tokens.append({**t, "price_usd": price.get("usd"), "change_24h": price.get("change_24h"), "value_usd": usd})
    priced_tokens.sort(key=lambda t: t.get("value_usd") or 0, reverse=True)

    native_usd = (bal * price_usd) if (bal is not None and price_usd) else None
    report["balances"] = {
        "native": {"symbol": "SOL", "amount": bal, "price_usd": price_usd, "value_usd": native_usd},
        "tokens": priced_tokens,
        "token_count": len(priced_tokens),
        "exists": account.get("exists"),
        "owner_program": account.get("owner_program"),
    }
    report["portfolio"] = {
        "total_value_usd": (native_usd or 0) + token_total if (native_usd is not None or token_total) else None,
        "native_value_usd": native_usd,
        "token_value_usd": token_total,
        "price_source": _price_source(native_price),
    }

    timeline = []
    for s in sigs:
        ts = s.get("blockTime")
        timeline.append(
            {
                "timestamp": _iso(ts),
                "type": "signature",
                "direction": "unknown",
                "counterparty": None,
                "value": None,
                "symbol": "SOL",
                "txid": s.get("signature"),
                "err": s.get("err"),
                "memo": s.get("memo"),
            }
        )
    timeline.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
    timestamps = [e["timestamp"] for e in timeline if e.get("timestamp")]
    report["activity"] = {
        "recent_tx_sample": len(sigs),
        "first_activity": min(timestamps) if timestamps else None,
        "last_activity": max(timestamps) if timestamps else None,
    }
    report["counterparties"] = []
    report["timeline"] = timeline[:60]
    report["identity"] = {"chain": "SOL", "address": address, "type": "account"}
    report["risk"] = _score_risk(goplus_flags=[], ofac={"listed": False}, is_contract=bool(account.get("is_executable")), is_new=(len(sigs) < 3))
    report["providers"] = ["Solana JSON-RPC", "CoinGecko"]
    report["errors"] = sol_errors
    report["summary"] = _summary(report)
    return report


# --------------------------------------------------------------------------- #
# XRP Ledger
# --------------------------------------------------------------------------- #
async def _analyze_xrp(address: str, target: detect.Target) -> dict:
    report: dict[str, Any] = {"target": {"input": target.raw, "chain": "XRP", "address": address}}
    account, lines, txs, ofac = await asyncio.gather(
        xrp.get_account(address),
        xrp.get_trustlines(address),
        xrp.get_transactions(address, 25),
        _safe(sanctions.screen("XRP", address)),
    )
    native_price = await _safe(prices.native_prices(["XRP"]), default={})
    price_usd = (native_price.get("XRP") or {}).get("usd")
    bal = _known_balance(account)
    xrp_errors: list[str] = [account["error"]] if account.get("error") else []
    if bal is None and not xrp_errors:
        xrp_errors.append(
            "Balance could not be read from the XRP Ledger. Holdings are unknown for this run, not zero."
        )

    trustlines = [
        {
            "currency": ln.get("currency"),
            "account": ln.get("account"),
            "balance": float(ln.get("balance") or 0),
            "limit": ln.get("limit"),
        }
        for ln in lines
    ]

    report["balances"] = {
        "native": {"symbol": "XRP", "amount": bal, "price_usd": price_usd,
                   "value_usd": (bal * price_usd) if (bal is not None and price_usd) else None},
        "trustlines": trustlines,
        "token_count": len(trustlines),
        "tokens": trustlines,
    }
    report["portfolio"] = {
        "total_value_usd": (bal * price_usd) if (bal is not None and price_usd) else None,
        "native_value_usd": (bal * price_usd) if (bal is not None and price_usd) else None,
        "token_value_usd": 0,
        "price_source": _price_source(native_price),
    }

    timeline = []
    for entry in txs:
        tx = entry.get("tx") or entry.get("tx_json") or {}
        meta = entry.get("meta") or {}
        ts = tx.get("date")
        ts = (ts + 946684800) if ts else None  # XRP epoch (2000-01-01)
        timeline.append(
            {
                "timestamp": _iso(ts),
                "type": tx.get("TransactionType") or "transaction",
                "direction": "out" if tx.get("Account") == address else "in",
                "counterparty": tx.get("Destination"),
                "value": (tx.get("Amount") / 1e6) if isinstance(tx.get("Amount"), int) else None,
                "symbol": "XRP",
                "value_usd": ((tx.get("Amount") / 1e6) * price_usd) if (isinstance(tx.get("Amount"), int) and price_usd) else None,
                "txid": tx.get("hash"),
                "result": meta.get("TransactionResult"),
            }
        )
    timeline.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
    timestamps = [e["timestamp"] for e in timeline if e.get("timestamp")]
    report["activity"] = {
        "recent_tx_sample": len(txs),
        "owner_count": account.get("owner_count"),
        "first_activity": min(timestamps) if timestamps else None,
        "last_activity": max(timestamps) if timestamps else None,
    }
    report["counterparties"] = []
    report["timeline"] = timeline[:60]
    report["identity"] = {"chain": "XRP", "address": address, "type": "account", "exists": account.get("exists")}
    report["risk"] = _score_risk(goplus_flags=[], ofac=ofac, is_contract=False, is_new=(len(txs) < 3))
    report["providers"] = ["XRPL cluster", "CoinGecko", "OFAC SDN"]
    report["errors"] = xrp_errors
    report["summary"] = _summary(report)
    return report


# --------------------------------------------------------------------------- #
# IP / host
# --------------------------------------------------------------------------- #
async def _analyze_ip(raw: str, target: detect.Target) -> dict:
    report: dict[str, Any] = {"target": {"input": raw, "kind": target.kind}}
    providers: list[str] = []
    errors: list[str] = []
    dns_data: dict = {}
    domain_data: dict = {}
    subdomains: dict = {}

    if target.kind == "host":
        resolved = await geo.resolve_host(raw)
        geo_data = resolved.get("geo") or {}
        report["target"]["host"] = raw
        report["target"]["addresses"] = resolved.get("addresses", [])
        report["target"]["primary_ip"] = resolved.get("primary_ip")
        if resolved.get("error"):
            errors.append(resolved["error"])
        # Hostname intelligence: DNS records, registration and subdomains.
        dns_data, domain_data, subdomains = await asyncio.gather(
            _safe(dnsintel.dns_records(raw), default={}),
            _safe(dnsintel.rdap_domain(raw), default={}),
            _safe(dnsintel.subdomains(raw), default={}),
            return_exceptions=False,
        )
        providers += ["Cloudflare DNS", "RDAP", "crt.sh"]
    else:
        geo_data = await geo.lookup_ip(raw)
        report["target"]["ip"] = raw

    tz = geo.local_time(geo_data.get("timezone_id"))
    report["geo"] = {**geo_data, **tz}

    anon = geo_data.get("anonymity") or {}
    report["identity"] = {
        "ip": geo_data.get("ip"),
        "type": geo_data.get("type"),
        "reverse_dns": geo_data.get("reverse_dns"),
        "isp": geo_data.get("isp"),
        "org": geo_data.get("org"),
        "asn": geo_data.get("asn"),
        "as_name": geo_data.get("as_name"),
        "asn_domain": geo_data.get("asn_domain"),
    }
    if anon:
        report["identity"]["anonymity"] = [k for k, v in anon.items() if v]

    if geo_data.get("rdap"):
        report["network_registration"] = geo_data["rdap"]
    if dns_data.get("records"):
        report["dns"] = dns_data["records"]
    if domain_data:
        report["domain"] = domain_data
    if subdomains and subdomains.get("count"):
        report["subdomains"] = subdomains

    providers += [s.get("name") for s in geo_data.get("sources", []) if s.get("name")]
    providers += ["RDAP.org", "zoneinfo", "Tor Project exit list"]

    conf = geo_data.get("confidence") or {}
    report["providers"] = list(dict.fromkeys(providers))
    report["errors"] = errors
    loc = ", ".join(
        p for p in [geo_data.get("city"), geo_data.get("region"), geo_data.get("country")] if p
    )
    if loc:
        report["summary"] = (
            f"{geo_data.get('ip', raw)} resolves to {loc} "
            f"({geo_data.get('latitude')}, {geo_data.get('longitude')}); "
            f"served by {geo_data.get('isp') or geo_data.get('org') or 'unknown ISP'}"
            f"{'; anonymity indicators present' if any(anon.values()) else ''}."
            f" Location confidence: {conf.get('level', 'unknown')}."
        )
    else:
        report["summary"] = f"Could not geolocate {raw}."
    return report


# --------------------------------------------------------------------------- #
# ENS
# --------------------------------------------------------------------------- #
async def _analyze_ens(name: str, target: detect.Target) -> dict:
    resolved = await ens.forward(name)
    if not resolved.get("resolved"):
        return {
            "target": {"input": name, "kind": "ens"},
            "identity": {"ens": name, "resolved": False},
            "providers": ["ensdata.net"],
            "errors": ["ENS name did not resolve to an address."],
            "summary": f"{name} did not resolve to an address.",
        }
    report = await _analyze_eth(
        resolved["address"],
        detect.Target(raw=name, kind="ens", chain="ETH", normalized=resolved["address"]),
        website=resolved.get("website"),
        ens_name=name,
    )
    report["target"]["input"] = name
    report["target"]["ens"] = name
    report["identity"]["ens"] = name
    report["identity"]["ens_resolved_from"] = name
    report["identity"]["ens_profile"] = {
        k: resolved.get(k)
        for k in (
            "avatar",
            "description",
            "url",
            "website",
            "twitter",
            "github",
            "email",
            "discord",
            "telegram",
            "pgp",
            "header",
        )
        if resolved.get(k)
    }
    report["providers"] = list({*report.get("providers", []), "ensdata.net"})
    report["summary"] = _summary(report)
    return report


# --------------------------------------------------------------------------- #
# Risk scoring
# --------------------------------------------------------------------------- #
def _score_risk(*, goplus_flags: list, ofac: Optional[dict], is_contract: bool, is_new: bool) -> dict:
    score = 0
    findings = []

    for flag in goplus_flags or []:
        key = flag.get("key")
        weight = config.RISK_WEIGHTS.get(key, 10)
        score += weight
        findings.append({"severity": _risk_level(min(weight * 2, 100)), "source": "GoPlus", "detail": flag.get("label")})

    if ofac and ofac.get("listed"):
        score += config.RISK_WEIGHTS["sanctioned"]
        findings.append({"severity": "critical", "source": "OFAC SDN", "detail": "Address appears on the OFAC SDN sanctions list"})

    if is_new:
        findings.append({"severity": "low", "source": "heuristics", "detail": "Very little on-chain history"})

    score = min(score, 100)
    return {
        "score": score,
        "level": _risk_level(score),
        "findings": findings,
        "ofac": ofac or {},
        "screened_by": [f.get("source") for f in findings] or ["no adverse signals"],
    }


def _summary(report: dict) -> str:
    parts = []
    ident = report.get("identity") or {}
    tgt = report.get("target") or {}
    chain = tgt.get("chain")
    addr = tgt.get("address") or tgt.get("ip") or tgt.get("input")
    if chain:
        parts.append(f"{chain} address {addr}")
    elif addr:
        parts.append(str(addr))
    label = ident.get("label")
    if label:
        parts.append(f"labelled '{label.get('name')}'")
    if ident.get("ens"):
        parts.append(f"ENS {ident['ens']}")
    port = report.get("portfolio") or {}
    port_total = port.get("total_value_usd") if isinstance(port, dict) else None
    if isinstance(port_total, (int, float)):
        parts.append(f"portfolio value ~${port_total:,.2f}")
    mc = report.get("multichain") or {}
    if mc.get("chains_with_funds"):
        mc_total = mc.get("total_value_usd")
        mc_total = mc_total if isinstance(mc_total, (int, float)) else 0
        parts.append(
            f"present on {mc['chains_with_funds']} EVM chains (~${mc_total:,.0f} combined)"
        )
    act = report.get("activity") or {}
    if act.get("tx_count") is not None:
        parts.append(f"{act['tx_count']} transactions")
    ego = report.get("ego_network") or {}
    if ego.get("counterparty_count"):
        parts.append(f"{ego['counterparty_count']} counterparties")
    taint = report.get("taint") or {}
    if taint.get("exposure_count"):
        parts.append(
            f"{taint['exposure_count']} taint exposure(s), worst {taint.get('worst_severity')}"
        )
    attr = report.get("attribution") or {}
    if attr.get("confidence") in ("confirmed", "probable") and attr.get("claim_count"):
        parts.append(f"identity {attr['confidence']}")
    risk = report.get("risk") or {}
    if risk:
        parts.append(f"risk {risk.get('level')} ({risk.get('score')}/100)")
    return "; ".join(parts) + "." if parts else "No summary available."


async def _safe(coro, default=None):
    try:
        return await coro
    except Exception:
        return default


def _known_balance(container: Any, key: str = "balance_native") -> Optional[float]:
    """Return a balance only when the provider actually reported one.

    A missing key means the provider did not answer, which is materially
    different from a confirmed zero balance. Returning ``None`` keeps the
    report honest: a failed lookup must never be rendered as "0", because that
    reads as a verified empty wallet.
    """
    if not isinstance(container, dict):
        return None
    value = container.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
async def analyze(raw: str) -> dict:
    report = await _dispatch(raw)
    _enrich_tx_origin(report)
    return report


def _enrich_tx_origin(report: dict) -> None:
    """Attach transaction-origin hints to any wallet report that has a timeline."""
    if report.get("tx_origin") or not report.get("timeline"):
        return
    try:
        origin = txorigin.analyze(
            report.get("timeline") or [],
            report.get("counterparties") or [],
            labels.label_eth,
        )
    except Exception:
        return
    if origin:
        report["tx_origin"] = origin


async def _dispatch(raw: str) -> dict:
    target = detect.detect(raw)
    if target.kind == "unknown":
        return {
            "target": {"input": raw, "kind": "unknown"},
            "errors": ["Unrecognized input. Paste an address, ENS name, IP or hostname."],
            "summary": "Unrecognized input.",
        }
    if target.kind == "ens":
        return await _analyze_ens(target.raw, target)
    if target.kind in ("ip", "host"):
        return await _analyze_ip(target.raw, target)
    chain = target.chain
    address = target.normalized or target.raw
    if chain == "ETH":
        return await _analyze_eth(address, target)
    if chain in ("BTC", "LTC"):
        return await _analyze_esplora(chain, address, target)
    if chain == "DOGE":
        return await _analyze_doge(address, target)
    if chain == "TRON":
        return await _analyze_tron(address, target)
    if chain == "SOL":
        return await _analyze_solana(address, target)
    if chain == "XRP":
        return await _analyze_xrp(address, target)
    return {"target": {"input": raw}, "errors": [f"Unsupported chain: {chain}"], "summary": "Unsupported chain."}
