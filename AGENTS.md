# AGENTS.md

Repository memory for ChainLens (crypto & network OSINT tool).

## What this is

FastAPI backend + dependency-light vanilla-JS frontend that turns a wallet
address, ENS name, IP, or hostname into one consolidated intelligence report.

## Layout

- `app/detect.py` — classifies raw input into `{kind, chain, normalized, notes}`.
- `app/analyzer.py` — orchestrates providers and shapes the report dict.
  Per-chain functions (`analyze_eth`, `analyze_btc`, `analyze_tron`, …) plus
  `analyze(query)` entrypoint. Report keys: `summary`, `identity`, `portfolio`,
  `balances`, `activity`, `timeline`, `counterparties`, `risk`, `geo`,
  `providers`, `errors`.
- `app/providers/*` — one module per upstream. All go through
  `providers/http.py::fetch_json` (shared async httpx client + in-process cache).
  `fetch_json` accepts a per-call `timeout` for slow endpoints (Blockscout's
  aggregated token list needs it).
- `app/providers/geo.py` — multi-source IP geolocation. Queries several
  providers in parallel and reduces them: per-field majority vote, coordinate
  consensus (prefers sources that agree on city), and an agreement-ratio
  confidence (`high`/`medium`/`low`). Also does PTR, RDAP network registration,
  and evidence-based anonymity detection.
- `app/providers/dnsintel.py` — DNS records (Cloudflare DoH), domain RDAP
  registration, and crt.sh certificate-transparency subdomains.
- `app/txorigin.py` — transaction-origin analysis. States plainly that a
  transaction has no IP and no location, then derives the two legitimate weaker
  signals: the hour-of-day activity clock (a timezone *hint*, never a location)
  and the jurisdiction of any labelled exchange or mixer the address touched
  (the service's jurisdiction, not the user's).
- `app/providers/linkedfootprint.py` — follows a wallet's *published website*
  (e.g. the ENS `url` record) to its hosting IP and geolocation. A wallet address
  has no IP or location of its own, so this is the only legitimate on-chain ->
  off-chain location link: it is a property of the website, never the address.
- `app/providers/blockscout.py` — deep EVM intelligence (tokens with logos and
  prices, NFTs, lifetime counters, verified-contract metadata), multi-chain.
- `app/static/` — `index.html`, `styles.css`, `app.js`. `app.js` renders the
  report JSON; `card()` accepts a string OR a DOM node as its body, `kv()`
  returns a DOM node (do not string-concatenate it).

## Conventions & gotchas

- Run with `python -m uvicorn app.main:app` (uvicorn is not on PATH).
- Providers are best-effort: wrap calls in `analyzer._safe(...)` and append to
  `report["errors"]` instead of raising. The report must always render.
- Anonymity flags are evidence, not votes: Tor is authoritative and may stand
  alone (checked against the Tor Project bulk exit list); proxy/VPN/hosting are
  noisy alone — ip-api flags datacenter IPs as proxies — so they need a second
  provider before being shown. `anonymity_detail` records who reported what.
- Token lists: Blockscout returns every ERC-20 balance. Rank by the explorer's
  own valuation and only price the head (per-contract CoinGecko calls are
  expensive); count the tail separately so the portfolio total stays honest.
- Prices: CoinGecko first, then Coinbase, then Kraken fallback (Kraken covers
  TRX, which Coinbase omits; Kraken pair keys are non-obvious, e.g.
  `XBTUSD` -> `XXBTZUSD`, so match by candidate key set).
- EVM: detect EIP-7702 delegation designators (`0xef0100` + 20 bytes) so a
  delegated EOA is not reported as a contract.
- TronGrid TRC-20: only `type == "Transfer"` events change balances. `Approval`
  events carry a uint256-max value and must be skipped.
- Bitcoin-family counterparties: the counterparty of a tx is the largest
  external party on the dominant side (receivers if net-in, senders if net-out).
- HTTP timeouts: `httpx` treats an explicit `timeout=None` as *no timeout*, not
  "use the client default", so `fetch_json` only forwards `timeout` when an
  override is set. Read/connect timeouts are also **not** retried: retrying a
  hung endpoint multiplies the wait by the retry count, which stalls a report
  when a public provider accepts the connection and never answers.
- EVM RPC: `_rpc` walks the endpoint list itself, so it disables `fetch_json`
  retries and uses a short timeout; otherwise a dead node multiplies the
  timeout across every URL in the list.
- Approvals: read the most recent transactions from the Blockscout **v2**
  (`/v2/addresses/{addr}/transactions`) cursor API, not v1 (v1 429s under
  bursts). Re-verify each allowance on-chain with `eth_call` before reporting it.
  Attribute spenders with curated labels first, then the explorer's
  `contract_name`, then an OFAC screen; dedupe and fetch concurrently.
- Blockscout `address_info` can hang for some addresses; the read/connect
  no-retry rule above keeps that from stalling the whole report.
- TronGrid `get_account` returns 400 for unknown/malformed addresses — treat it
  as a not-found account, not an error, so the report still renders.
- Lint before committing: `python3 -m pyflakes app`.

## Investigator features (the differentiators)

Balances, tokens, NFTs and sanctions screening are commodity — every explorer
has them. These four sections are what make the report investigative:

- **Entity attribution** (`app/providers/attribution.py`). Fuses curated labels,
  the explorer's own label set (Open Labels Initiative tags carry entity names,
  category tags and *verified service domains*), reverse ENS, GoPlus and OFAC
  into one dossier. Every claim carries its source and a confidence grade:
  `confirmed` (authoritative label/sanctions list), `probable` (reverse-ENS
  name — owner-controlled, can be set to anything). Never merge a probable hint
  into a confirmed identity.
- **Fund-flow tracing + taint exposure** (`app/fundflow.py`). Builds the ego
  network of counterparties and flags direct (1-hop) and bounded indirect
  (2-hop) exposure to sanctioned/mixer/flagged counterparties. Exposure is a
  fact about a transaction, not intent: dust links are downgraded, 2-hop
  exposure is labelled weak, and both are caveated in the UI.
- **Cross-chain presence** (`app/providers/multichain.py`). The same 0x address
  is valid on every EVM chain; an explorer shows one. This sweeps 8 chains
  (ETH, Base, Arbitrum, Optimism, Polygon, Gnosis, zkSync, Scroll) via Blockscout
  v2 and consolidates value. Some instances (Base especially) intermittently
  403 behind a WAF; a failed chain degrades to an error entry, never a crash.
- **Counterparty network graph.** Dependency-light inline SVG in `app.js`
  (`drawEgoGraph`), monochrome to match the palette; node size is tx count,
  filled = taint-flagged.

Counterparty attribution comes from the `from`/`to` **objects** in Blockscout
`/v2/addresses/{addr}/token-transfers` — they carry the full label set, which the
plain transactions endpoint does not.

## UI

Black-and-white monochrome palette (`--bg`, `--text`, `--white`, grayscale
borders). Severity is conveyed with weight/fill, not colour, so the palette
stays black & white. Generous spacing via `--gap`/`--pad`. The Leaflet basemap
is forced grayscale (`.leaflet-tile-pane` filter) to match. An IP report shows a
Location card (region, IP, coordinates, local time, confidence badge, pinpoint
map) plus Network & registration; a host report adds DNS, domain, and
subdomains.

## Boundary (keep honest)

A wallet address is not an IP and does not reveal a person's location. Only
IP/hostname targets get real geolocation. For ENS targets, the linked website's
hosting IP is geolocated as a clearly separate signal. Never fabricate a
wallet->location mapping. IP geolocation is city-level at best; the map draws an
uncertainty halo rather than implying street-level precision.

## Testing

`python3 -m pyflakes app` for lint. Manual smoke tests cover ETH, ENS, BTC, LTC,
DOGE, TRON, SOL, XRP, IPv4, IPv6, hostname, a sanctioned address (expect
`risk.level == "critical"`), a wallet with live token approvals (expect a
non-empty `approvals.active`), an active wallet (expect `clustering.signals`),
and garbage input (expect a friendly error). For the investigator features,
expect `attribution.claims` non-empty for a labelled address, `ego_network`
populated for an active wallet, a 2-hop `taint` exposure for a sanctioned
address, and `multichain.chains_with_funds >= 1` for a funded EVM address.
Static assets are referenced with a `?v=N` query in `index.html`; bump it when
`app.js`/`styles.css` change so the browser does not serve a stale copy.
