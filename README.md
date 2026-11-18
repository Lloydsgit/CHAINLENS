# ChainLens — Crypto & Network OSINT

Paste a wallet address, ENS name, IP, or hostname and get one consolidated
intelligence report: balances, token and NFT holdings, transaction activity,
counterparties, identity signals, exposure and token risk, IP geolocation with a
pinpoint map and local time, DNS and domain registration, anonymity indicators,
and sanctions screening.

## One important boundary

A blockchain address is **not** an IP address, and on-chain activity does not
reveal a person's location. There is no legitimate provider that maps
`0x…` or `bc1…` to a street address, and any tool claiming to do so is either
fabricating the result or correlating off-chain leaks.

ChainLens is honest about this:

- **IP / hostname targets** get real geolocation — country, region/city,
  coordinates on a pinpoint map, ISP/ASN, timezone, and current local time —
  from several public IP intelligence providers whose answers are cross-checked.
- **Wallet targets** get everything that is actually public on-chain: balances,
  tokens and NFTs, transaction history, counterparties, labels, exposure and
  token risk, and sanctions status.
- **Transaction origin** — every wallet report includes a *transaction origin*
  card. It is honest that a transaction carries no IP and no location, and shows
  the two signals that do exist: an hour-of-day activity clock with a timezone
  hint, and the jurisdiction of any labelled exchange or mixer the address
  touched. Both are labelled as hints with their confounders.
- **Linked footprint** — when a wallet *publishes* a website (for example
  through an ENS `url` record), ChainLens follows that link: it resolves the
  site's hosting IP, geolocates it on the same map, and reads the page's public
  metadata. This is clearly labelled as a property of the **website**, not the
  wallet. It is the one legitimate on-chain → off-chain location signal, and it
  only exists when the wallet itself publishes a link.

## Supported targets

| Kind | Example | Data returned |
| --- | --- | --- |
| EVM address | `0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045` | balance, nonce, contract/EOA, ERC-20 holdings, NFTs, transfers, counterparties, token risk |
| ENS name | `vitalik.eth` | resolved address + reverse records, then the full EVM report |
| Bitcoin | `bc1q…` | balance, UTXO stats, transactions, counterparties, fees |
| Litecoin | `Lc…` | same as Bitcoin |
| Dogecoin | `D…` | balance, UTXO stats, transactions |
| TRON | `T…` | TRX balance, TRC-20 holdings, transfers, counterparties |
| Solana | base58 pubkey | SOL balance, SPL tokens, recent signatures |
| XRP Ledger | `r…` | XRP balance, account flags, recent transactions |
| IPv4 / IPv6 | `8.8.8.8` | geolocation with consensus confidence, ASN, ISP, reverse DNS, RDAP network registration, anonymity indicators, timezone, local time, map |
| Hostname | `cloudflare.com` | resolved IPs, the IP report, plus DNS records, domain registration, and CT-log subdomains |

## Providers

All sources are public, no API key required:

- **Chains** — Ethereum JSON-RPC (Cloudflare), Blockstream Esplora (BTC),
  litecoinspace.org (LTC), Dogechain, TronGrid, Solana JSON-RPC, XRPL public
  cluster.
- **Tokens & metadata** — Ethplorer and Blockscout (ERC-20 balances, NFTs,
  verified-contract metadata), GoPlus Labs (address security and per-token
  risk), ensdata.net (ENS).
- **Prices** — CoinGecko, with Coinbase and Kraken fallbacks so valuations keep
  working when a source rate-limits.
- **IP intelligence** — ipwho.is, ip-api.com, ipinfo.io and ipapi.is, reduced by
  consensus; Tor Project bulk exit list for authoritative Tor detection; RDAP
  for network registration.
- **Domains** — Cloudflare DNS-over-HTTPS for records, RDAP for registration,
  crt.sh for certificate-transparency subdomains.
- **Sanctions** — OFAC SDN list via the 0xB10C public mirror.

Every provider is best-effort: if one is slow or down, the report still renders
with a note in **Sources & notes** rather than failing.

## Running

```bash
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Then open `http://localhost:8000`.

### API

- `GET /api/health` — liveness and version.
- `POST /api/detect` — classify a query without fetching anything.
  Body: `{"query": "vitalik.eth"}`.
- `POST /api/analyze` — full report.
  Body: `{"query": "0xd8dA…"}`.

## Design notes

- `app/detect.py` classifies input; `app/analyzer.py` orchestrates providers and
  shapes the report; `app/providers/*` each wrap one upstream.
- Provider calls run concurrently and are cached in-process, so repeat lookups
  are fast and upstreams are not hammered.
- The report is JSON-first; the UI in `app/static/` is a dependency-light
  renderer over that JSON.

## Disclaimer

ChainLens aggregates public data for research and compliance triage. Results can
be incomplete or stale, and a clean sanctions screen is not proof of legitimacy.
Verify independently before acting on any result.
