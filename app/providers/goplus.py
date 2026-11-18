"""GoPlus Labs address-security provider (keyless).

Returns risk flags for an EVM address: sanctions, mixers, darkweb, phishing,
money laundering, cybercrime and more. This is the primary machine-readable
risk signal for EVM addresses.
"""
from __future__ import annotations

from . import http

BASE = "https://api.gopluslabs.io/api/v1"

FLAG_LABELS = {
    "sanctioned": "Sanctioned entity",
    "mixer": "Mixer / tumbler exposure",
    "darkweb_transactions": "Darkweb transactions",
    "phishing_activities": "Phishing activity",
    "money_laundering": "Money laundering",
    "cybercrime": "Cybercrime",
    "stealing_attack": "Theft / stealing attack",
    "blackmail_activities": "Blackmail activity",
    "fake_kyc": "Fake KYC",
    "financial_crime": "Financial crime",
    "blacklist_doubt": "Blacklist doubt",
    "malicious_mining_activities": "Malicious mining",
    "honeypot_related_address": "Honeypot related",
    "gas_abuse": "Gas abuse",
    "fake_token": "Fake token",
    "reinit": "Reinitialization risk",
    "number_of_malicious_contracts_created": "Malicious contracts created",
}


async def address_security(address: str, chain_id: int = 1) -> dict:
    try:
        data = await http.fetch_json(
            f"{BASE}/address_security/{address}",
            params={"chain_id": chain_id},
            ttl=300,
        )
    except Exception as exc:
        return {"available": False, "error": str(exc)}
    result = (data or {}).get("result") or {}
    if not result:
        return {"available": False}

    flags = []
    for key, label in FLAG_LABELS.items():
        raw = result.get(key)
        if raw in (None, "", "0", 0):
            continue
        if key == "number_of_malicious_contracts_created":
            flags.append({"key": key, "label": label, "value": raw})
        else:
            flags.append({"key": key, "label": label, "value": True})

    return {
        "available": True,
        "source": "GoPlus Labs",
        "flags": flags,
        "is_contract": result.get("contract_address") == "1",
        "raw": result,
    }


# Token-level risk signals, mapped to human labels. Keys are GoPlus field names.
TOKEN_FLAG_LABELS = {
    "is_honeypot": "Honeypot (cannot sell)",
    "cannot_sell_all": "Cannot sell entire balance",
    "is_blacklisted": "Blacklist function present",
    "is_whitelisted": "Whitelist function present",
    "is_mintable": "Mintable supply",
    "is_proxy": "Proxy contract",
    "hidden_owner": "Hidden owner",
    "can_take_back_ownership": "Owner can reclaim ownership",
    "owner_change_balance": "Owner can change balances",
    "transfer_pausable": "Transfers can be paused",
    "trading_cooldown": "Trading cooldown enforced",
    "personal_slippage_modifiable": "Owner can change tax",
    "slippage_modifiable": "Tax can be modified",
    "selfdestruct": "Self-destruct capable",
    "external_call": "External call in transfers",
    "anti_whale_modifiable": "Anti-whale limit modifiable",
    "fake_token": "Fake token",
    "airdrop_scam": "Airdrop scam",
}


async def token_security(chain_id: str, contract: str) -> dict:
    """Risk signals for a single ERC-20 contract."""
    try:
        data = await http.fetch_json(
            f"{BASE}/token_security/{chain_id}",
            params={"contract_addresses": contract},
            ttl=900,
        )
    except Exception as exc:
        return {"available": False, "error": str(exc)}
    result = (data or {}).get("result") or {}
    info = result.get(contract.lower()) or result.get(contract) or {}
    if not info:
        return {"available": False}

    def _flag(val) -> bool:
        return str(val).lower() in ("1", "true", "yes")

    flags = [
        {"key": key, "label": label}
        for key, label in TOKEN_FLAG_LABELS.items()
        if _flag(info.get(key))
    ]

    def _pct(val):
        try:
            return round(float(val) * 100, 2)
        except (TypeError, ValueError):
            return None

    return {
        "available": True,
        "source": "GoPlus Labs",
        "contract": contract,
        "name": info.get("token_name"),
        "symbol": info.get("token_symbol"),
        "holder_count": info.get("holder_count"),
        "total_supply": info.get("total_supply"),
        "is_open_source": _flag(info.get("is_open_source")),
        "is_honeypot": _flag(info.get("is_honeypot")),
        "buy_tax": _pct(info.get("buy_tax")),
        "sell_tax": _pct(info.get("sell_tax")),
        "lp_holder_count": info.get("lp_holder_count"),
        "owner_address": info.get("owner_address"),
        "creator_address": info.get("creator_address"),
        "flags": flags,
    }
