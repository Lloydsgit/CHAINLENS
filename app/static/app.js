/* ChainLens OSINT console — renders analyzer reports into cards. */

const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, cls, html) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (html !== undefined) node.innerHTML = html;
  return node;
};

/* ---------- formatting ---------- */
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function money(v) {
  if (v === null || v === undefined || isNaN(v)) return "—";
  const n = Number(v);
  if (Math.abs(n) >= 1e9) return "$" + (n / 1e9).toFixed(2) + "B";
  if (Math.abs(n) >= 1e6) return "$" + (n / 1e6).toFixed(2) + "M";
  if (Math.abs(n) >= 1e3) return "$" + n.toLocaleString(undefined, { maximumFractionDigits: 0 });
  return "$" + n.toLocaleString(undefined, { maximumFractionDigits: n < 1 ? 6 : 2 });
}
function num(v, dp = 6) {
  if (v === null || v === undefined || isNaN(v)) return "—";
  const n = Number(v);
  if (n === 0) return "0";
  if (Math.abs(n) < 1) return n.toPrecision(Math.max(dp, 4)).replace(/0+$/, "").replace(/\.$/, "");
  return n.toLocaleString(undefined, { maximumFractionDigits: dp });
}
function shortAddr(a, n = 8) {
  if (!a) return "—";
  return a.length > n * 2 + 3 ? `${a.slice(0, n)}…${a.slice(-n)}` : a;
}
function timeAgo(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  const diff = (Date.now() - d.getTime()) / 1000;
  const units = [["y", 31536000], ["mo", 2592000], ["d", 86400], ["h", 3600], ["m", 60]];
  for (const [label, secs] of units) {
    if (diff >= secs) return `${Math.floor(diff / secs)}${label} ago`;
  }
  return "just now";
}
function fmtDate(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toISOString().replace("T", " ").slice(0, 19) + " UTC"; }
  catch { return iso; }
}
function pct(v) {
  if (v === null || v === undefined || isNaN(v)) return "";
  const n = Number(v);
  return `<span class="${n >= 0 ? "pos" : "neg"}">${n >= 0 ? "▲" : "▼"} ${Math.abs(n).toFixed(2)}%</span>`;
}
function has(v) { return v !== null && v !== undefined && v !== ""; }
function ts(v) { return String(v ?? ""); }

/* ---------- card helpers ---------- */
function card(title, bodyHtml, span) {
  const c = el("div", "card" + (span ? " " + span : ""));
  if (title) c.appendChild(el("h3", null, `<span class="dot"></span>${esc(title)}`));
  if (typeof bodyHtml === "string") c.insertAdjacentHTML("beforeend", bodyHtml);
  else if (bodyHtml) c.appendChild(bodyHtml);
  return c;
}

function kv(rows) {
  const dl = el("dl", "kv");
  rows.filter(([, v]) => v !== undefined && v !== null && v !== "").forEach(([k, v]) => {
    dl.appendChild(el("dt", null, esc(k)));
    dl.appendChild(el("dd", null, v));
  });
  return dl;
}

function metric(k, v, sub, cls = "") {
  return `<div class="metric"><div class="k">${esc(k)}</div><div class="v ${cls}">${v}</div>${sub ? `<div class="sub">${sub}</div>` : ""}</div>`;
}

/* ---------- renderers ---------- */
function renderBanner(r) {
  const risk = r.risk || {};
  const badge = risk.level
    ? `<span class="tag ${risk.level}">${esc(risk.level)} risk · ${risk.score}/100</span>`
    : "";
  const prov = (r.providers || []).length;
  return card(null, `
    <div class="banner">
      <div class="lead">${esc(r.summary || "Analysis complete.")}</div>
      <div class="tags">${badge}<span class="tag grey">${prov} providers</span>${(r.providers || []).slice(0, 5).map((p) => `<span class="tag grey">${esc(p)}</span>`).join("")}</div>
    </div>`);
}

function renderPortfolio(r) {
  const p = r.portfolio || {};
  const b = r.balances || {};
  const nat = b.native || {};
  const rows = [
    metric("Total value", money(p.total_value_usd), "across all assets"),
    metric("Native balance", `${num(nat.amount)} ${esc(nat.symbol || "")}`, nat.price_usd ? `${money(nat.price_usd)} / ${esc(nat.symbol)}` : ""),
    metric("Native value", money(nat.value_usd), ""),
    metric("Tokens", num(b.token_count ?? 0, 0), b.tokens_shown && b.tokens_shown < b.token_count ? `top ${b.tokens_shown} shown` : "distinct assets"),
  ];
  if (b.unconfirmed_native) rows.push(metric("Unconfirmed", num(b.unconfirmed_native), "mempool"));
  return card("Portfolio", `<div class="metrics">${rows.join("")}</div>`, "span-6");
}

function renderIdentity(r) {
  const id = r.identity || {};
  const t = r.target || {};
  const rows = [];
  if (t.chain) rows.push(["Chain", esc(t.chain)]);
  if (t.address) rows.push(["Address", `<span class="mono-big">${esc(t.address)}</span><span class="copy" data-copy="${esc(t.address)}">copy</span>`]);
  if (id.ens) rows.push(["ENS", `<span class="addr-link">${esc(id.ens)}</span>`]);
  if (id.label) rows.push(["Label", `<span class="tag">${esc(id.label.name)}</span> <span class="tag grey">${esc(id.label.category)}</span>`]);
  if (id.type) rows.push(["Type", esc(id.type)]);
  if (id.contract_name) rows.push(["Name", esc(id.contract_name)]);
  if (id.public_tags && id.public_tags.length) rows.push(["Tags", id.public_tags.map((x) => `<span class="tag grey">${esc(x)}</span>`).join(" ")]);
  if (id.creator) rows.push(["Creator", `<span class="addr-link" data-addr="${esc(id.creator)}">${esc(shortAddr(id.creator, 10))}</span>`]);
  if (id.implementation) rows.push(["Implementation", `<span class="addr-link" data-addr="${esc(id.implementation)}">${esc(shortAddr(id.implementation, 10))}</span>`]);
  if (id.bytecode_size) rows.push(["Bytecode size", `${num(id.bytecode_size, 0)} bytes`]);
  if (id.contract) rows.push(["Contract", `${esc(id.contract.name || "?")} (${esc(id.contract.symbol || "?")})`]);
  const vc = id.verified_contract;
  if (vc) rows.push(["Verified source", vc.verified ? "yes" : "no"]);
  if (vc && vc.compiler) rows.push(["Compiler", esc(vc.compiler)]);
  if (vc && vc.language) rows.push(["Language", esc(vc.language)]);
  if (vc && vc.license) rows.push(["License", esc(vc.license)]);
  if (id.owner_program) rows.push(["Owner program", esc(shortAddr(id.owner_program, 10))]);
  const prof = id.ens_profile || {};
  if (prof.avatar) rows.push(["Avatar", `<img src="${esc(prof.avatar)}" alt="" style="width:38px;height:38px;border-radius:9px;object-fit:cover" onerror="this.style.display='none'">`]);
  ["description", "url", "twitter", "github", "email", "telegram", "discord"].forEach((k) => {
    if (prof[k]) rows.push([k[0].toUpperCase() + k.slice(1), esc(prof[k])]);
  });
  return card("Identity", kv(rows), "span-6");
}

function renderActivity(r) {
  const a = r.activity || {};
  const rows = [
    metric("Transactions", num(a.lifetime_transactions ?? a.tx_count ?? a.recent_tx_sample ?? 0, 0), a.lifetime_transactions ? "lifetime" : "sampled"),
    metric("Oldest sampled", a.first_activity ? timeAgo(a.first_activity) : "—", a.first_activity ? fmtDate(a.first_activity) : "no history"),
    metric("Last active", a.last_activity ? timeAgo(a.last_activity) : "—", a.last_activity ? fmtDate(a.last_activity) : ""),
  ];
  if (has(a.lifetime_token_transfers)) rows.push(metric("Token transfers", num(a.lifetime_token_transfers, 0), "lifetime"));
  if (has(a.outgoing_tx_count)) rows.push(metric("Outgoing", num(a.outgoing_tx_count, 0), "nonce"));
  if (has(a.received)) rows.push(metric("Received", num(a.received), "lifetime"));
  if (has(a.sent)) rows.push(metric("Sent", num(a.sent), "lifetime"));
  if (has(a.chain_tip_height)) rows.push(metric("Chain tip", num(a.chain_tip_height, 0), "block height"));
  if (has(a.owner_count)) rows.push(metric("Owner count", num(a.owner_count, 0), "ledger objects"));
  return card("Activity", `<div class="metrics">${rows.join("")}</div>`);
}

function renderTokens(r) {
  const tokens = (r.balances || {}).tokens || [];
  if (!tokens.length) return null;
  const total = (r.portfolio || {}).token_value_usd || 0;
  const rows = tokens.slice(0, 40).map((t) => {
    const label = t.symbol ? `${esc(t.symbol)}` : esc(shortAddr(t.contract || t.mint || "?", 6));
    const pctCell = has(t.change_24h) ? pct(t.change_24h) : "";
    const icon = t.logo
      ? `<img class="tok-icon" src="${esc(t.logo)}" alt="" onerror="this.style.display='none'">`
      : "";
    const holders = has(t.holders) ? `<div class="muted" style="font-size:12px">${num(t.holders, 0)} holders</div>` : "";
    return `<tr>
      <td><div class="tok-cell">${icon}<div><b>${label}</b><div class="muted" style="font-size:12px">${esc(t.name || "")}</div>${holders}</div></div></td>
      <td class="num">${num(t.amount)}</td>
      <td class="num">${has(t.price_usd) ? money(t.price_usd) : "—"}</td>
      <td class="num">${pctCell}</td>
      <td class="num">${has(t.value_usd) ? money(t.value_usd) : "—"}</td>
    </tr>`;
  }).join("");
  const shown = Math.min(tokens.length, 40);
  const note = tokens.length > shown ? ` · showing top ${shown} of ${tokens.length}` : "";
  return card("Token holdings", `
    <table><thead><tr><th>Asset</th><th class="num">Amount</th><th class="num">Price</th><th class="num">24h</th><th class="num">Value</th></tr></thead>
    <tbody>${rows}</tbody></table>
    <div class="muted" style="margin-top:16px;font-size:13px">Token value total: ${money(total)}${note}</div>`);
}

function renderNfts(r) {
  const n = r.nfts || {};
  const cols = n.collections || [];
  if (!cols.length) return null;
  const rows = cols.slice(0, 24).map((c) => {
    const icon = c.icon ? `<img class="tok-icon" src="${esc(c.icon)}" alt="" onerror="this.style.display='none'">` : "";
    return `<tr>
      <td><div class="tok-cell">${icon}<div><b>${esc(c.name || "Unknown collection")}</b><div class="muted" style="font-size:12px">${esc(c.symbol || "")} · ${esc(c.type || "NFT")}</div></div></div></td>
      <td class="num">${num(c.count, 0)}</td>
    </tr>`;
  }).join("");
  return card("NFT collections", `
    <table><thead><tr><th>Collection</th><th class="num">Held</th></tr></thead><tbody>${rows}</tbody></table>
    <div class="muted" style="margin-top:16px;font-size:13px">${n.count} collections in this wallet</div>`);
}

function renderAttribution(r) {
  const a = r.attribution;
  if (!a || !(a.claims || []).length) return null;
  const c = card("Entity attribution", null, "span-6");

  const conf = a.confidence || "none";
  c.appendChild(el("div", "metrics", [
    metric("Confidence", `<span class="sev ${esc(conf)}">${esc(conf)}</span>`, "strongest source"),
    metric("Claims", String(a.claim_count ?? 0), "sourced"),
    metric("Entity type", esc(a.entity_type || "—"), "inferred"),
  ].join("")));

  const rank = { confirmed: 0, probable: 1, possible: 2 };
  const claims = [...(a.claims || [])].sort((x, y) => (rank[x.confidence] ?? 9) - (rank[y.confidence] ?? 9));
  const rows = claims.map((cl) => {
    const value = cl.kind === "domain"
      ? `<a href="https://${esc(cl.value)}" target="_blank" rel="noopener">${esc(cl.value)}</a>`
      : esc(cl.value);
    return `<div class="finding">
      <span class="sev ${esc(cl.confidence)}">${esc(cl.confidence)}</span>
      <span><strong>${value}</strong>
      <div class="muted" style="font-size:12px;margin-top:2px">${esc(cl.kind)} · ${esc(cl.source)}${cl.detail ? ` · ${esc(cl.detail)}` : ""}</div></span>
    </div>`;
  }).join("");
  c.appendChild(el("div", "findings", rows));
  if (a.caveat) c.appendChild(el("p", "scope-note", esc(a.caveat)));
  return c;
}

function renderTaint(r) {
  const t = r.taint;
  const ego = r.ego_network;
  if (!t && !ego) return null;
  const c = card("Fund flow & taint exposure", null, "span-6");

  const worst = (t || {}).worst_severity;
  const metrics = [
    metric("Counterparties", String((ego || {}).counterparty_count ?? 0), "distinct, in window"),
    metric("Direct exposure", String((t || {}).direct_count ?? 0), "1-hop flagged"),
    metric("Indirect exposure", String((t || {}).indirect_count ?? 0), "2-hop flagged"),
    metric("Worst", worst ? `<span class="sev ${esc(worst)}">${esc(worst)}</span>` : `<span class="sev low">none</span>`, "taint severity"),
  ];
  c.appendChild(el("div", "metrics", metrics.join("")));

  const exposures = (t || {}).exposures || [];
  if (exposures.length) {
    c.appendChild(el("div", "section-label", "Exposure paths"));
    c.appendChild(el("div", "findings", exposures.map((e) => {
      const who = e.label
        ? `<strong>${esc(e.label)}</strong> <span class="muted mono">${esc(shortAddr(e.address, 6))}</span>`
        : `<span class="addr-link" data-addr="${esc(e.address)}">${esc(shortAddr(e.address, 8))}</span>`;
      const hop = e.hop === 2 ? `<span class="tag grey">2-hop</span>` : `<span class="tag grey">direct</span>`;
      const reasons = (e.reasons || []).map((x) => esc(x.detail)).join("; ");
      const via = e.via ? ` <span class="muted">via ${esc(shortAddr(e.via, 6))}</span>` : "";
      return `<div class="finding">
        <span class="sev ${esc(e.severity)}">${esc(e.severity)}</span>
        <span>${who} ${hop}${via}
        <div class="muted" style="font-size:12.5px;margin-top:2px">${reasons}</div>
        <div class="muted" style="font-size:12px;margin-top:2px">${e.tx_count ?? 0} tx${e.native_in || e.native_out ? ` · in ${num(e.native_in || 0, 4)} / out ${num(e.native_out || 0, 4)}` : ""}</div></span>
      </div>`;
    }).join("")));
  } else if (t && t.checked) {
    c.appendChild(el("div", "conf-badge", "No exposure to flagged counterparties in the sampled window."));
  }

  // Ego network graph
  if (ego && (ego.nodes || []).length) {
    c.appendChild(el("div", "section-label", "Counterparty network"));
    const holder = el("div", "netgraph");
    holder.id = "ego-graph";
    c.appendChild(holder);
    c.appendChild(el("p", "scope-note", "Node size is transaction count; filled nodes are flagged by taint screening, hollow nodes are unlabelled. Centre is the target address."));
  }

  if (t && t.note) c.appendChild(el("p", "scope-note", esc(t.note)));
  return c;
}

function drawEgoGraph(r) {
  const ego = r.ego_network;
  const holder = $("#ego-graph");
  if (!ego || !holder) return;
  const nodes = (ego.nodes || []).slice(0, 18);
  if (!nodes.length) return;

  const W = holder.clientWidth || 560;
  const H = 340;
  const cx = W / 2, cy = H / 2;
  const R = Math.min(W, H) / 2 - 46;
  const maxTx = Math.max(...nodes.map((n) => n.tx_count || 1), 1);
  const taint = r.taint || {};
  const flagged = new Set((taint.exposures || []).map((e) => e.address));

  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("class", "ego-svg");

  const pos = [];
  nodes.forEach((n, i) => {
    const a = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
    pos.push([cx + R * Math.cos(a), cy + R * Math.sin(a)]);
  });

  // edges
  pos.forEach(([x, y], i) => {
    const line = document.createElementNS(NS, "line");
    line.setAttribute("x1", cx); line.setAttribute("y1", cy);
    line.setAttribute("x2", x); line.setAttribute("y2", y);
    const bad = flagged.has(nodes[i].address);
    line.setAttribute("class", "ego-edge" + (bad ? " bad" : ""));
    const w = 1 + ((nodes[i].tx_count || 1) / maxTx) * 3;
    line.setAttribute("stroke-width", w.toFixed(1));
    svg.appendChild(line);
  });

  // centre
  const centre = document.createElementNS(NS, "circle");
  centre.setAttribute("cx", cx); centre.setAttribute("cy", cy); centre.setAttribute("r", 13);
  centre.setAttribute("class", "ego-node centre");
  svg.appendChild(centre);
  const cl = document.createElementNS(NS, "text");
  cl.setAttribute("x", cx); cl.setAttribute("y", cy + 30);
  cl.setAttribute("text-anchor", "middle"); cl.setAttribute("class", "ego-label");
  cl.textContent = "target";
  svg.appendChild(cl);

  // counterparties
  pos.forEach(([x, y], i) => {
    const n = nodes[i];
    const rr = 5 + ((n.tx_count || 1) / maxTx) * 9;
    const bad = flagged.has(n.address);
    const circ = document.createElementNS(NS, "circle");
    circ.setAttribute("cx", x); circ.setAttribute("cy", y); circ.setAttribute("r", rr.toFixed(1));
    circ.setAttribute("class", "ego-node" + (bad ? " bad" : ""));
    const title = document.createElementNS(NS, "title");
    title.textContent = `${n.address}\n${n.tx_count} tx · in ${num(n.native_in || 0, 4)} / out ${num(n.native_out || 0, 4)}${n.label ? "\n" + n.label : ""}`;
    circ.appendChild(title);
    svg.appendChild(circ);
    const lbl = document.createElementNS(NS, "text");
    lbl.setAttribute("x", x); lbl.setAttribute("y", y + rr + 11);
    lbl.setAttribute("text-anchor", "middle"); lbl.setAttribute("class", "ego-label");
    lbl.textContent = n.label || shortAddr(n.address, 4);
    svg.appendChild(lbl);
  });

  holder.appendChild(svg);
}

function renderMultichain(r) {
  const m = r.multichain;
  if (!m || !(m.chains || []).length) return null;
  const c = card("Cross-chain presence", null, "span-6");
  c.appendChild(el("div", "metrics", [
    metric("Chains active", `${m.chains_active}/${m.chains_checked}`, "address exists"),
    metric("Chains with funds", String(m.chains_with_funds ?? 0), "non-zero value"),
    metric("Total value", money(m.total_value_usd), "all chains combined"),
  ].join("")));

  const max = Math.max(...m.chains.map((x) => x.chain_value_usd || 0), 1);
  const rows = m.chains.filter((x) => !x.error && ((x.tx_count || 0) > 0 || (x.balance || 0) > 0 || (x.token_count || 0) > 0))
    .map((x) => {
      const w = ((x.chain_value_usd || 0) / max) * 100;
      const bal = x.balance ? `${num(x.balance, 5)} ${esc(x.symbol || "")}` : "0";
      return `<div class="bar-row">
        <div class="bar-top">
          <span><strong>${esc(x.name || x.chain)}</strong>${x.is_contract ? ` <span class="tag grey">contract</span>` : ""}</span>
          <span class="bar-meta">${bal} · ${x.token_count || 0} tokens · ${money(x.chain_value_usd)}</span>
        </div>
        <div class="bar-track"><div class="bar-fill" style="width:${w}%"></div></div>
      </div>`;
    }).join("");
  c.appendChild(el("div", "bars-list", rows || `<div class="muted">No activity found on any supported chain.</div>`));
  if ((m.errors || []).length) {
    c.appendChild(el("p", "scope-note", `${m.errors.length} chain(s) unavailable this run.`));
  }
  return c;
}

function renderCounterparties(r) {
  const cps = r.counterparties || [];
  if (!cps.length) return null;
  const max = Math.max(...cps.map((c) => c.tx_count || 0), 1);
  const rows = cps.slice(0, 15).map((c) => {
    const w = ((c.tx_count || 0) / max) * 100;
    const label = c.label ? `<span class="tag grey">${esc(c.label)}</span>` : "";
    const val = c.value ? `<span class="muted">${num(c.value)}</span>` : "";
    return `<div class="bar-row">
      <div class="bar-top">
        <span class="addr-link" data-addr="${esc(c.address)}">${esc(shortAddr(c.address, 12))}</span>
        <span class="bar-meta">${c.tx_count} tx ${val} ${label}</span>
      </div>
      <div class="bar-track"><div class="bar-fill" style="width:${w}%"></div></div>
    </div>`;
  }).join("");
  return card("Top counterparties", `<div class="bars-list">${rows}</div>`);
}

function renderTimeline(r) {
  const tl = r.timeline || [];
  if (!tl.length) return null;
  const rows = tl.slice(0, 40).map((e) => {
    const amt = e.value !== null && e.value !== undefined
      ? `<span class="amt">${num(e.value)} ${esc(e.symbol || "")}</span> ${e.value_usd ? `<span class="muted">(${money(e.value_usd)})</span>` : ""}`
      : "";
    const cp = e.counterparty ? `<span class="muted">·</span> <span class="addr-link" data-addr="${esc(e.counterparty)}">${esc(shortAddr(e.counterparty, 8))}</span>` : "";
    const txn = e.txid ? `<span class="muted">·</span> <span class="muted">${esc(shortAddr(e.txid, 6))}</span>` : "";
    const type = e.type ? `<span class="tag grey" style="font-size:11px">${esc(e.type)}</span>` : "";
    return `<div class="tl-item ${esc(e.direction || "")}">
      <span class="tl-time">${fmtDate(e.timestamp).slice(0, 10)}</span>
      <span class="tl-body">${amt} ${cp} ${txn} ${type}</span>
    </div>`;
  }).join("");
  return card("Recent timeline", `<div class="timeline">${rows}</div>`);
}

function renderRisk(r) {
  const risk = r.risk || {};
  const score = risk.score ?? 0;
  const level = risk.level || "low";
  // Severity is expressed with weight/fill rather than colour so the palette
  // stays strictly black and white.
  const stroke = level === "low" ? "rgba(255,255,255,0.35)" : "#ffffff";
  const circumference = 2 * Math.PI * 42;
  const dash = (score / 100) * circumference;
  const gauge = `
    <div class="risk-head">
      <div class="gauge">
        <svg width="96" height="96">
          <circle cx="48" cy="48" r="42" stroke="rgba(255,255,255,0.07)" stroke-width="8" fill="none"></circle>
          <circle cx="48" cy="48" r="42" stroke="${stroke}" stroke-width="8" fill="none"
                  stroke-linecap="round" stroke-dasharray="${dash} ${circumference}"></circle>
        </svg>
        <div class="num">${score}<small>/100</small></div>
      </div>
      <div>
        <div class="risk-level">${esc(level)} risk</div>
        <div class="muted" style="font-size:13px;margin-top:8px">
          Screened by: ${esc((risk.ofac && risk.ofac.source) || "GoPlus Labs, OFAC SDN")}
        </div>
      </div>
    </div>`;
  const findings = (risk.findings || []).map((f) => `
    <div class="finding">
      <span class="sev ${esc(f.severity)}">${esc(f.severity)}</span>
      <span><b>${esc(f.source)}</b> — ${esc(f.detail)}</span>
    </div>`).join("");
  const body = gauge + `<div class="findings">${findings || '<div class="finding"><span class="sev low">clean</span><span>No adverse signals detected from sanctions or address-security screening.</span></div>'}</div>`;
  return card("Risk &amp; compliance", body);
}

function renderExposure(r) {
  const e = r.exposure || {};
  const flagged = e.flagged_tokens || [];
  if (!flagged.length && !e.erc20_positions && !e.nft_collections) return null;
  const c = card("Exposure &amp; token risk", null, "span-6");
  c.appendChild(kv([
    ["ERC-20 positions", num(e.erc20_positions ?? 0, 0)],
    ["NFT collections", num(e.nft_collections ?? 0, 0)],
    ["Contract interactions", e.has_contract_interactions ? "yes" : "no"],
  ]));
  if (flagged.length) {
    const box = el("div", "findings");
    box.style.marginTop = "22px";
    flagged.forEach((t) => {
      const flags = (t.flags || []).map((f) => esc(f.label || f)).join(", ");
      const tax = (has(t.sell_tax) && Number(t.sell_tax) > 0) ? ` · sell tax ${t.sell_tax}%` : "";
      box.appendChild(el("div", "finding",
        `<span class="sev high">token</span><span><b>${esc(t.symbol || shortAddr(t.contract, 6))}</b> — ${flags}${tax}</span>`));
    });
    c.appendChild(box);
  }
  return c;
}

/* ---------- network / geolocation ---------- */
function renderLocation(r) {
  const g = r.geo || {};
  if (!g.country && !g.latitude) return null;
  const conf = g.confidence || {};
  const rows = [];
  if (has(g.ip)) rows.push(["IP address", `<span class="mono-big">${esc(g.ip)}</span>${has(g.type) ? ` <span class="tag grey">${esc(g.type)}</span>` : ""}`]);
  if (has(g.reverse_dns)) rows.push(["Reverse DNS", `<span class="mono-big">${esc(g.reverse_dns)}</span>`]);
  if (has(g.city) || has(g.region) || has(g.country)) {
    rows.push(["Region", esc([g.city, g.region, g.country].filter(Boolean).join(", "))]);
  }
  if (has(g.district)) rows.push(["District", esc(g.district)]);
  if (has(g.postal)) rows.push(["Postal code", esc(g.postal)]);
  if (has(g.continent)) rows.push(["Continent", esc(g.continent)]);
  if (has(g.latitude) && has(g.longitude)) {
    const ll = `${Number(g.latitude).toFixed(6)}, ${Number(g.longitude).toFixed(6)}`;
    rows.push(["Coordinates", `<span class="mono-big">${ll}</span><span class="copy" data-copy="${ll}">copy</span>`]);
    rows.push(["Pinpoint", `<a class="addr-link" href="https://www.openstreetmap.org/?mlat=${g.latitude}&mlon=${g.longitude}#map=13/${g.latitude}/${g.longitude}" target="_blank" rel="noopener">open in map ↗</a>`]);
  }
  if (has(g.timezone_id)) rows.push(["Timezone", `${esc(g.timezone_id)}${has(g.utc_offset) ? ` (${esc(g.utc_offset)})` : ""}`]);
  if (has(g.local_time)) rows.push(["Local time", `<span class="mono-big">${esc(g.local_time)}</span>`]);
  if (has(g.is_dst)) rows.push(["Daylight saving", g.is_dst ? "active" : "inactive"]);
  if (has(g.is_eu)) rows.push(["EU member", g.is_eu ? "yes" : "no"]);
  if (has(g.calling_code)) rows.push(["Calling code", `+${esc(g.calling_code)}`]);
  if (has(g.currency)) rows.push(["Currency", esc(g.currency)]);

  const c = card("Location", null, "span-6");
  c.appendChild(kv(rows));

  if (conf.level) {
    const badge = el("div", "conf-badge" + (conf.level === "high" ? " high" : ""),
      `${esc(conf.level)} confidence · ${esc(conf.note || "")}`);
    badge.style.marginTop = "22px";
    c.appendChild(badge);
  }
  if (has(g.latitude) && has(g.longitude)) {
    const wrap = el("div", "map-wrap");
    wrap.style.cssText = "margin-top:18px;height:340px";
    wrap.id = "geo-map";
    c.appendChild(wrap);
  }
  return c;
}

function renderNetwork(r) {
  const g = r.geo || {};
  const id = r.identity || {};
  const reg = r.network_registration || {};
  const rows = [];
  if (has(id.isp)) rows.push(["ISP", esc(id.isp)]);
  if (has(id.org)) rows.push(["Organisation", esc(id.org)]);
  if (has(id.asn)) rows.push(["ASN", `<span class="mono-big">${esc(id.asn)}</span>`]);
  if (has(id.as_name)) rows.push(["AS name", esc(id.as_name)]);
  if (has(g.asn_domain)) rows.push(["ASN domain", esc(g.asn_domain)]);
  if (has(g.capital)) rows.push(["Country capital", esc(g.capital)]);
  if (has(g.borders) && Array.isArray(g.borders)) rows.push(["Borders", esc(g.borders.join(", "))]);
  if (has(reg.name)) rows.push(["Network", esc(reg.name)]);
  if (has(reg.handle)) rows.push(["Net handle", esc(reg.handle)]);
  if (has(reg.type)) rows.push(["Allocation", esc(reg.type)]);
  if (reg.cidrs && reg.cidrs.length) rows.push(["Prefixes", reg.cidrs.map((x) => `<span class="tag grey">${esc(x)}</span>`).join(" ")]);
  if (has(reg.start_address)) rows.push(["Range", `${esc(reg.start_address)} – ${esc(reg.end_address || "")}`]);
  if (has(reg.last_changed)) rows.push(["Last changed", fmtDate(reg.last_changed)]);
  const ents = (reg.entities || []).filter((e) => e.name || e.handle);
  if (ents.length) {
    rows.push(["Registered to", ents.slice(0, 4).map((e) => `<div>${esc(e.name || e.handle)} <span class="muted">${esc(e.roles || "")}</span></div>`).join("")]);
  }
  const detail = g.anonymity_detail || {};
  const active = Object.keys(g.anonymity || {}).filter((k) => g.anonymity[k]);
  if (active.length) {
    rows.push(["Anonymity", active.map((k) => {
      const d = detail[k] || {};
      const note = d.reported_by ? ` <span class="muted">(${d.reported_by}/${d.of})</span>` : "";
      return `<span class="tag">${esc(k)}</span>${note}`;
    }).join(" ")]);
  }
  if (!rows.length) return null;
  return card("Network &amp; registration", kv(rows), "span-6");
}

function renderDns(r) {
  const dns = r.dns || {};
  const keys = Object.keys(dns);
  if (!keys.length) return null;
  const blocks = keys.map((type) => {
    const items = dns[type].map((rec) => {
      let val = rec.value || "";
      if (type === "TXT" && val.length > 90) val = val.slice(0, 90) + "…";
      return `<div class="dns-rec"><span class="mono-big">${esc(val)}</span>${has(rec.ttl) ? ` <span class="muted">ttl ${esc(ts(rec.ttl))}</span>` : ""}</div>`;
    }).join("");
    return `<div class="dns-block"><div class="dns-type">${esc(type)} <span class="muted">${dns[type].length}</span></div>${items}</div>`;
  }).join("");
  return card("DNS records", `<div class="dns-grid">${blocks}</div>`, "span-12");
}

function renderDomain(r) {
  const d = r.domain || {};
  const sub = r.subdomains || {};
  if (!d.domain && !sub.count) return null;
  const rows = [];
  if (has(d.domain)) rows.push(["Domain", `<span class="mono-big">${esc(d.domain)}</span>`]);
  if (has(d.registrar)) rows.push(["Registrar", esc(d.registrar)]);
  if (has(d.created)) rows.push(["Registered", fmtDate(d.created)]);
  if (has(d.updated)) rows.push(["Last updated", fmtDate(d.updated)]);
  if (has(d.expires)) rows.push(["Expires", fmtDate(d.expires)]);
  if (d.status && d.status.length) rows.push(["Status", d.status.map((s) => `<span class="tag grey">${esc(s)}</span>`).join(" ")]);
  if (d.nameservers && d.nameservers.length) rows.push(["Nameservers", d.nameservers.map((n) => `<div class="mono-big">${esc(n)}</div>`).join("")]);
  if (has(d.dnssec)) rows.push(["DNSSEC", d.dnssec ? "signed" : "unsigned"]);
  const ents = (d.entities || []).filter((e) => e.name || e.org || e.email);
  if (ents.length) rows.push(["Contacts", ents.slice(0, 5).map((e) => `<div>${esc(e.name || e.org || "—")} <span class="muted">${esc(e.roles || "")}</span>${e.email ? ` <span class="muted">${esc(e.email)}</span>` : ""}</div>`).join("")]);
  const c = card("Domain registration", kv(rows), "span-6");
  if (sub.count) {
    const names = (sub.names || []).map((n) => `<span class="tag grey">${esc(n)}</span>`).join(" ");
    const issuers = (sub.issuers || []).map((i) => `<div class="muted" style="font-size:13px">${esc(i)}</div>`).join("");
    const extra = el("div", null, `
      <div style="margin-top:24px">
        <div style="font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted-2);margin-bottom:14px">
          ${sub.count} subdomains in certificate transparency
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:8px">${names}</div>
        ${issuers ? `<div style="margin-top:20px"><div style="font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted-2);margin-bottom:10px">Certificate issuers</div>${issuers}</div>` : ""}
      </div>`);
    c.appendChild(extra);
  }
  return c;
}

function renderHostTarget(r) {
  const t = r.target || {};
  if (t.kind !== "host") return null;
  const rows = [];
  if (has(t.host)) rows.push(["Hostname", `<span class="mono-big">${esc(t.host)}</span>`]);
  if (t.addresses && t.addresses.length) rows.push(["Resolved IPs", t.addresses.map((a) => `<span class="mono-big">${esc(a)}</span>`).join("<br>")]);
  if (has(t.primary_ip)) rows.push(["Primary IP", `<span class="mono-big">${esc(t.primary_ip)}</span>`]);
  return card("Target", kv(rows), "span-6");
}

let leafletMap = null;
let leafletMapEl = null;

function drawMap(lat, lon, label, spreadKm, nodeId) {
  const node = document.getElementById(nodeId || "geo-map");
  if (!node || typeof L === "undefined") return;
  if (leafletMap && leafletMapEl === node) { leafletMap.remove(); leafletMap = null; }
  leafletMapEl = node;
  leafletMap = L.map(node, { zoomControl: true, attributionControl: false, scrollWheelZoom: false })
    .setView([lat, lon], spreadKm && spreadKm > 100 ? 5 : 9);
  L.tileLayer("https://basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    subdomains: "abcd",
    maxZoom: 19,
  }).addTo(leafletMap);
  // A soft halo conveys the city-level uncertainty of IP geolocation, which
  // is honest about precision while still giving a clear pinpoint.
  L.circle([lat, lon], {
    radius: 12000, color: "rgba(255,255,255,0.5)", weight: 1,
    fillColor: "#ffffff", fillOpacity: 0.07,
  }).addTo(leafletMap);
  L.circleMarker([lat, lon], {
    radius: 8, color: "#ffffff", weight: 2, fillColor: "#ffffff", fillOpacity: 1,
  }).addTo(leafletMap).bindPopup(label || "Target location");
  setTimeout(() => leafletMap && leafletMap.invalidateSize(), 120);
}

function renderLinkedFootprint(r) {
  const lf = r.linked_footprint;
  if (!lf || (!lf.url && !lf.host)) return null;
  const g = lf.geo || {};
  const c = card("Linked footprint", null, "span-6");

  const note = el("p", "scope-note",
    `A wallet address has no IP or location of its own. What follows is the hosting footprint of the website this wallet publishes` +
    (lf.source ? ` (${esc(lf.source)})` : "") + ` — a property of the site, not the address.`);
  c.appendChild(note);

  const rows = [];
  rows.push(["Website", `<a class="addr-link" href="${esc(lf.url)}" target="_blank" rel="noopener">${esc(lf.url)} ↗</a>`]);
  if (has(lf.title)) rows.push(["Page title", esc(lf.title)]);
  if (has(lf.description)) rows.push(["Description", esc(lf.description)]);
  if (has(lf.host)) rows.push(["Hostname", `<span class="mono-big">${esc(lf.host)}</span>`]);
  if (lf.addresses && lf.addresses.length) rows.push(["Resolved IPs", lf.addresses.map((a) => `<span class="mono-big">${esc(a)}</span>`).join("<br>")]);
  if (has(lf.ip)) rows.push(["Hosting IP", `<span class="mono-big">${esc(lf.ip)}</span><span class="copy" data-copy="${esc(lf.ip)}">copy</span>`]);
  if (has(g.city) || has(g.region) || has(g.country)) rows.push(["Hosted in", esc([g.city, g.region, g.country].filter(Boolean).join(", "))]);
  if (has(g.latitude) && has(g.longitude)) {
    const ll = `${Number(g.latitude).toFixed(6)}, ${Number(g.longitude).toFixed(6)}`;
    rows.push(["Coordinates", `<span class="mono-big">${ll}</span>`]);
  }
  if (has(g.timezone_id)) rows.push(["Timezone", `${esc(g.timezone_id)}${has(g.local_time) ? ` · local ${esc(g.local_time)}` : ""}`]);
  if (lf.technologies && lf.technologies.length) {
    rows.push(["Technologies", lf.technologies.map((t) => `<span class="tag grey">${esc(t)}</span>`).join(" ")]);
  }
  if (has(lf.reachable)) rows.push(["Reachable", lf.reachable ? "yes" : "no"]);
  c.appendChild(kv(rows));

  if (has(g.latitude) && has(g.longitude)) {
    const wrap = el("div", "map-wrap");
    wrap.style.cssText = "margin-top:18px;height:300px";
    wrap.id = "footprint-map";
    c.appendChild(wrap);
  }
  const caveat = el("div", "conf-badge",
    "City-level hosting location. Shared hosting and CDNs place many sites in the same datacenter.");
  caveat.style.marginTop = "20px";
  c.appendChild(caveat);
  return c;
}

function renderApprovals(r) {
  const a = r.approvals;
  if (!a || !a.available) return null;
  const c = card("Token approvals", null, "span-6");

  const active = a.active || [];
  const metrics = [
    metric("Active approvals", String(a.active_count ?? 0), "live, verified on-chain"),
    metric("Unlimited", String(a.unlimited_count ?? 0), "no spending cap"),
    metric("Scanned", String(a.scanned_transactions ?? 0), "transactions"),
    metric("Distinct", String(a.distinct_approvals ?? 0), "approval calls seen"),
  ];
  c.appendChild(el("div", "metrics", metrics.join("")));

  const findings = a.findings || [];
  if (findings.length) {
    c.appendChild(el("div", "section-label", "Findings"));
    c.appendChild(el("div", "findings", findings.map((f) =>
      `<div class="finding"><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span><span>${esc(f.detail)}</span></div>`
    ).join("")));
  }

  if (active.length) {
    const rows = active.map((x) => {
      const who = x.spender_label
        ? `<strong>${esc(x.spender_label)}</strong> <span class="muted mono">${esc(shortAddr(x.spender, 6))}</span>`
        : `<span class="addr-link" data-addr="${esc(x.spender)}">${esc(shortAddr(x.spender, 8))}</span>`;
      const tags = [];
      if (x.nft) tags.push(`<span class="tag grey">NFT operator</span>`);
      if (x.unlimited) tags.push(`<span class="tag high">unlimited</span>`);
      if (x.sanctioned) tags.push(`<span class="tag critical">sanctioned</span>`);
      if (x.live_state === "unknown") tags.push(`<span class="tag grey">state unknown</span>`);
      const token = x.token_label ? `<strong>${esc(x.token_label)}</strong>` : `<span class="mono">${esc(shortAddr(x.token, 6))}</span>`;
      return `<tr><td>${token}</td><td>${who} ${tags.join(" ")}</td><td class="mono muted">${esc(timeAgo(x.last_seen))}</td></tr>`;
    }).join("");
    c.appendChild(el("div", "section-label", "Active allowances"));
    c.appendChild(el("table", "mini-table",
      `<thead><tr><th>Token</th><th>Spender</th><th>Approved</th></tr></thead><tbody>${rows}</tbody>`));
  } else {
    c.appendChild(el("div", "conf-badge", "No active approvals found in the scanned window."));
  }

  if (a.coverage) c.appendChild(el("p", "scope-note", esc(a.coverage)));
  return c;
}

function renderClustering(r) {
  const cl = r.clustering;
  if (!cl || !cl.available || !(cl.signals || []).length) return null;
  const c = card("Clustering & behaviour", null, "span-6");
  c.appendChild(el("p", "scope-note", esc(cl.caveat || "")));

  const blocks = cl.signals.map((s) => {
    const items = (s.items || []).map((it) => {
      if (it.address) {
        return `<span class="addr-link" data-addr="${esc(it.address)}">${esc(shortAddr(it.address, 6))}</span><span class="muted"> · ${it.tx_count}× ${it.total !== undefined ? num(it.total, 4) + " " + esc(cl.native_symbol || "") : ""}</span>`;
      }
      if (it.block !== undefined) {
        return `<span class="muted">block ${esc(it.block)} · ${it.recipients} recipients</span>`;
      }
      if (it.to) {
        return `<span class="muted">${esc(num(it.value, 4))} ${esc(cl.native_symbol || "")} → </span><span class="addr-link" data-addr="${esc(it.to)}">${esc(shortAddr(it.to, 6))}</span>`;
      }
      return "";
    }).filter(Boolean);
    return `<div class="finding">
      <span class="sev ${esc(s.confidence)}">${esc(s.confidence)}</span>
      <span><strong>${esc(s.label)}</strong><div class="muted" style="font-size:12.5px;margin-top:2px">${esc(s.detail)}</div>
      ${items.length ? `<div class="signal-items">${items.join("</div><div class=\"signal-items\">")}</div>` : ""}
      <div class="muted" style="font-size:12px;margin-top:6px;font-style:italic">${esc(s.caveat)}</div></span>
    </div>`;
  }).join("");
  c.appendChild(el("div", "findings", blocks));
  return c;
}

function renderTxOrigin(r) {
  const t = r.tx_origin;
  if (!t) return null;
  const c = card("Transaction origin", null, "span-6");

  c.appendChild(el("p", "scope-note", esc(t.explanation || "")));

  const rows = [];
  if (has(t.sample)) rows.push(["Transactions sampled", String(t.sample)]);
  if (t.window && t.window.first) rows.push(["Sampled window", `${fmtDate(t.window.first)} → ${fmtDate(t.window.last)}`]);

  const clock = t.activity_clock_utc || {};
  const tz = t.timezone_hints || {};
  if (tz.available) {
    const hints = (tz.hints || []).map((h) =>
      `<span class="tag grey">${esc(h.utc_offset)} <span class="muted">${Math.round((h.waking_hours_fit || 0) * 100)}%</span></span>`
    ).join(" ");
    rows.push(["Timezone hint", `${hints}<div class="muted" style="margin-top:6px;font-size:12.5px">best fit ${Math.round((tz.best_fit || 0) * 100)}% of activity in waking hours · sample ${tz.sample}</div>`]);
  } else if (tz.reason) {
    rows.push(["Timezone hint", `<span class="muted">${esc(tz.reason)}</span>`]);
  }
  if (clock.peak_hours_utc && clock.peak_hours_utc.length) {
    rows.push(["Busiest hours (UTC)", clock.peak_hours_utc.map((h) => `<span class="tag grey">${String(h).padStart(2, "0")}:00</span>`).join(" ")]);
  }
  c.appendChild(kv(rows));

  // Possible operating regions (from the inferred offsets).
  const pr = tz.possible_regions || {};
  if (pr.available) {
    const offsetTags = (pr.offsets_considered || []).map((o) => `<span class="tag grey">${esc(o)}</span>`).join(" ");
    const regionBlocks = (pr.regions || []).map((reg) => {
      const chips = (reg.countries || [])
        .slice(0, 14)
        .map((co) => `<span class="country-chip" title="${esc(co.name)}">${co.flag || ""} ${esc(co.code)}</span>`)
        .join(" ");
      const more = reg.country_count > 14 ? `<span class="muted" style="font-size:12px"> +${reg.country_count - 14} more</span>` : "";
      return `<div class="region-block">
        <div class="region-head"><span class="region-name">${esc(reg.region)}</span>
          <span class="muted">${reg.country_count} countries · ${reg.zone_count} zones</span></div>
        <div class="region-chips">${chips}${more}</div>
      </div>`;
    }).join("");
    const block = el("div", null,
      `<div class="section-label">Possible operating regions <span class="conf-badge">${esc(pr.confidence || "low")} confidence</span></div>
       <div class="muted" style="font-size:12.5px;margin-bottom:12px">Offsets in play: ${offsetTags || "—"} — the places that share the address's inferred active hours.</div>
       <div class="regions">${regionBlocks}</div>
       <div class="scope-note" style="margin-top:16px">${esc(pr.caveat || "")}</div>`);
    c.appendChild(block);
  }

  // hour-of-day histogram
  const hours = clock.hours || [];
  if (hours.length === 24) {
    const max = Math.max(...hours, 1);
    const bars = hours.map((v, h) => {
      const pct = (v / max) * 100;
      const label = String(h).padStart(2, "0");
      return `<div class="hour-col" title="${label}:00 UTC — ${v} tx">
        <div class="hour-track"><div class="hour-fill" style="height:${pct}%"></div></div>
        <div class="hour-lab">${label}</div>
      </div>`;
    }).join("");
    const wrap = el("div", null,
      `<div style="font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted-2);margin:22px 0 12px">Activity by hour (UTC)</div>
       <div class="hour-hist">${bars}</div>`);
    c.appendChild(wrap);
  }

  const venues = t.venues || [];
  if (venues.length) {
    const items = venues.map((v) =>
      `<div class="finding"><span class="sev medium">${esc(v.category || "venue")}</span>
        <span><strong>${esc(v.label)}</strong>${v.jurisdiction ? ` — <span class="muted">${esc(v.jurisdiction)}</span>` : ""}
        <span class="muted"> · ${v.tx_count || 0} tx</span></span></div>`
    ).join("");
    const block = el("div", null,
      `<div style="font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted-2);margin:22px 0 12px">Venues touched (service jurisdiction)</div>
       <div class="findings">${items}</div>
       ${t.venue_note ? `<div class="scope-note" style="margin-top:18px">${esc(t.venue_note)}</div>` : ""}`);
    c.appendChild(block);
  } else {
    c.appendChild(el("div", "conf-badge", "No labelled exchange or mixer in the sampled counterparties."));
  }
  return c;
}

function renderProviders(r) {
  const rows = (r.providers || []).map((p) => `<span class="tag grey">${esc(p)}</span>`).join("");
  const errs = (r.errors || []).map((e) => `<div class="finding"><span class="sev medium">note</span><span>${esc(e)}</span></div>`).join("");
  const body = `<div class="tags">${rows}</div>${errs ? `<div class="findings" style="margin-top:18px">${errs}</div>` : ""}`;
  return card("Sources &amp; notes", body);
}

/* ---------- main render ---------- */
function render(report) {
  const results = $("#results");
  results.innerHTML = "";
  results.hidden = false;
  const grid = el("div", "grid");

  grid.appendChild(renderBanner(report));

  const kind = (report.target || {}).kind;
  if (kind === "ip" || kind === "host") {
    const loc = renderLocation(report);
    if (loc) grid.appendChild(loc);
    const host = renderHostTarget(report);
    if (host) grid.appendChild(host);
    const net = renderNetwork(report);
    if (net) grid.appendChild(net);
    const dom = renderDomain(report);
    if (dom) grid.appendChild(dom);
    const dns = renderDns(report);
    if (dns) grid.appendChild(dns);
  } else {
    grid.appendChild(renderPortfolio(report));
    grid.appendChild(renderIdentity(report));
    const attr = renderAttribution(report);
    if (attr) grid.appendChild(attr);
    grid.appendChild(renderActivity(report));
    const mc = renderMultichain(report);
    if (mc) grid.appendChild(mc);
    const fp = renderLinkedFootprint(report);
    if (fp) grid.appendChild(fp);
    const txo = renderTxOrigin(report);
    if (txo) grid.appendChild(txo);
    const taint = renderTaint(report);
    if (taint) grid.appendChild(taint);
    const appr = renderApprovals(report);
    if (appr) grid.appendChild(appr);
    const clust = renderClustering(report);
    if (clust) grid.appendChild(clust);
    const tokens = renderTokens(report);
    if (tokens) grid.appendChild(tokens);
    const nfts = renderNfts(report);
    if (nfts) grid.appendChild(nfts);
    grid.appendChild(renderRisk(report));
    const exp = renderExposure(report);
    if (exp) grid.appendChild(exp);
    const cps = renderCounterparties(report);
    if (cps) grid.appendChild(cps);
    const tl = renderTimeline(report);
    if (tl) grid.appendChild(tl);
  }
  grid.appendChild(renderProviders(report));

  results.appendChild(grid);
  wireInteractions(results);
  drawEgoGraph(report);
  const g = report.geo || {};
  if (g.latitude && g.longitude) {
    drawMap(g.latitude, g.longitude, g.ip || (report.target || {}).input || "",
      (g.confidence || {}).coordinate_spread_km, "geo-map");
  }
  const lfg = (report.linked_footprint || {}).geo || {};
  if (lfg.latitude && lfg.longitude) {
    drawMap(lfg.latitude, lfg.longitude, (report.linked_footprint || {}).host || "Linked website",
      (lfg.confidence || {}).coordinate_spread_km, "footprint-map");
  }
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

function wireInteractions(root) {
  root.querySelectorAll("[data-copy]").forEach((node) => {
    node.addEventListener("click", () => {
      navigator.clipboard?.writeText(node.dataset.copy);
      node.textContent = "copied";
      setTimeout(() => (node.textContent = "copy"), 1200);
    });
  });
  root.querySelectorAll("[data-addr]").forEach((node) => {
    node.addEventListener("click", () => {
      $("#query").value = node.dataset.addr;
      runSearch(node.dataset.addr);
    });
  });
}

/* ---------- search flow ---------- */
let busy = false;

async function runSearch(query) {
  if (busy) return;
  busy = true;
  const status = $("#status");
  const results = $("#results");
  const btn = $("#go");
  btn.disabled = true;
  $(".label", btn).hidden = true;
  $(".spinner", btn).hidden = false;
  results.hidden = true;
  status.hidden = false;
  status.className = "status";
  status.innerHTML = `<div class="bars"><i></i><i></i><i></i><i></i><i></i></div>Aggregating on-chain and network intelligence…`;

  try {
    const resp = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query }),
    });
    if (!resp.ok) {
      const detail = await resp.json().catch(() => ({}));
      throw new Error(detail.detail || `Request failed (${resp.status})`);
    }
    const report = await resp.json();
    status.hidden = true;
    render(report);
  } catch (err) {
    status.className = "status error";
    status.innerHTML = `<b>Analysis failed.</b><br>${esc(err.message)}`;
  } finally {
    busy = false;
    btn.disabled = false;
    $(".label", btn).hidden = false;
    $(".spinner", btn).hidden = true;
  }
}

/* ---------- init ---------- */
$("#search-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const q = $("#query").value.trim();
  if (q) runSearch(q);
});
document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    $("#query").value = chip.dataset.q;
    runSearch(chip.dataset.q);
  });
});

function tick() {
  $("#clock").textContent = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
}
tick();
setInterval(tick, 1000);
