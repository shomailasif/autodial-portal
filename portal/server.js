const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { openDb, registerCustomer, processHeartbeat, setDisabled, markStaleOffline, allCustomers, getCustomerByToken, logCall, allCalls, getCallById, updateCustomer, setCallList, saveLeads } = require("./db");
const { HEARTBEAT_INTERVAL_MS, STALE_AFTER_MS, heartbeatResponse } = require("../shared/protocol");
const { sendEmail, listOutbox } = require("./mailer");
const { issueSession, verifySession, sessionFromCookieHeader, checkPassword, adminPassword } = require("./auth");
const { searchLeads } = require("./find-leads");

/**
 * Magic Dialer - admin cloud platform.
 *
 * A dependency-free HTTP server the admin can host anywhere (free cloud host).
 * It keeps the list of customer PCs, their health, disable state, editable
 * sales forms, call lists and internet-found leads. The agent PC
 * ====heartbeat====> portal on /api/heartbeat; the admin works from the
 * business-platform dashboard on "/".
 */

async function start({ dbPath = path.join(__dirname, "portal.db"), port = 8787, adminPassword } = {}) {
  const db = await openDb(dbPath);

  setInterval(() => { markStaleOffline(db, STALE_AFTER_MS + 2000); }, HEARTBEAT_INTERVAL_MS);

  // Find leads for customers on its own, on a schedule. On by default so the
  // platform works out of the box; operators can opt out with LEAD_AUTO=0.
  {
    const hours = Math.max(1, Math.min(24, parseFloat(process.env.LEAD_AUTO_HOURS) || 6));
    setInterval(async () => {
      try {
        const rows = await allCustomers(db);
        for (const c of rows) {
          const want = !(c.settings && c.settings.searchEnabled === false);
          const old = (c.leads_searched_at || 0) < Date.now() - 1000 * 60 * 60 * 24;
          if (process.env.LEAD_AUTO === "0" || !want || !old || !c.product) continue;
          const leads = await searchLeads({ product: c.product, count: 10 });
          if (leads.length) await saveLeads(db, c.token, leads);
        }
      } catch { /* scheduler must never crash the portal */ }
    }, 1000 * 60 * 60 * hours);
  }

  async function readBody(req) {
    let data = "";
    for await (const chunk of req) data += chunk;
    try { return JSON.parse(data || "{}"); } catch { return {}; }
  }

  const match = (urlPath, pattern) => {
    const m = String(urlPath).match(pattern);
    return m ? { token: decodeURIComponent(m[1]) } : null;
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    const method = req.method;
    const send = (code, obj, extraHeaders = {}) => {
      const body = typeof obj === "string" ? obj : JSON.stringify(obj);
      res.writeHead(code, {
        "Content-Type": typeof obj === "string" ? "text/html; charset=utf-8" : "application/json",
        "Access-Control-Allow-Origin": "*",
        ...extraHeaders,
      });
      res.end(body);
    };

    const isAdmin = verifySession(sessionFromCookieHeader(req.headers.cookie));

    // --- Admin login page + handler ---
    if (url.pathname === "/login" && method === "GET") return send(200, loginHtml());
    if (url.pathname === "/login" && method === "POST") {
      const body = await readBody(req);
      if (checkPassword(body.password, adminPassword)) {
        return send(200, { ok: true }, { "Set-Cookie": `session=${issueSession()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400` });
      }
      return send(401, { error: "Wrong password" });
    }
    if (url.pathname === "/logout" && method === "POST") {
      return send(200, { ok: true }, { "Set-Cookie": "session=; Path=/; HttpOnly; Max-Age=0" });
    }

    // --- Heartbeat from a customer's PC (no login - the agent must work) ---
    if (url.pathname === "/api/heartbeat" && method === "POST") {
      const body = await readBody(req);
      const out = await processHeartbeat(db, { token: body.token });
      return send(200, heartbeatResponse({ ok: out.ok, disabled: out.disabled, config: out.config, reason: out.reason }));
    }

    // --- Customer admin actions (ADMIN ONLY) ---
    const cmToken = match(url.pathname, /^\/api\/customer\/([^/]+)$/);
    const cmCallList = match(url.pathname, /^\/api\/customer\/([^/]+)\/calllist$/);
    const cmLeads = match(url.pathname, /^\/api\/customer\/([^/]+)\/leads$/);
    const cmLeadsSearch = match(url.pathname, /^\/api\/customer\/([^/]+)\/leads\/search$/);
    const cmLeadsRemove = match(url.pathname, /^\/api\/customer\/([^/]+)\/leads\/remove$/);

    if (cmToken && method === "GET") {
      if (!isAdmin) return send(401, { error: "Admin login required" });
      return send(200, { customer: await getCustomerByToken(db, cmToken.token) });
    }
    if (cmToken && method === "PATCH") {
      if (!isAdmin) return send(401, { error: "Admin login required" });
      const body = await readBody(req);
      const c = await updateCustomer(db, cmToken.token, {
        product: body.product,
        leadFields: Array.isArray(body.leadFields) ? body.leadFields : undefined,
        contactEmail: body.contactEmail,
        persona: body.persona,
        settings: body.settings,
      });
      return c ? send(200, { ok: true, customer: c }) : send(404, { error: "Customer not found" });
    }
    if (cmCallList && method === "POST") {
      if (!isAdmin) return send(401, { error: "Admin login required" });
      const body = await readBody(req);
      const c = await setCallList(db, cmCallList.token, body.numbers);
      return c ? send(200, { ok: true, callList: c.call_list }) : send(404, { error: "Customer not found" });
    }
    if (cmLeads && method === "GET") {
      if (!isAdmin) return send(401, { error: "Admin login required" });
      const c = await getCustomerByToken(db, cmLeads.token);
      return c ? send(200, { leads: c.leads_found, searchedAt: c.leads_searched_at }) : send(404, { error: "Customer not found" });
    }
    if (cmLeadsSearch && method === "POST") {
      if (!isAdmin) return send(401, { error: "Admin login required" });
      const c = await getCustomerByToken(db, cmLeadsSearch.token);
      if (!c) return send(404, { error: "Customer not found" });
      if (!c.product) return send(200, { leads: [], searchedAt: null, error: "Set the sales form first (no product to search for)." });
      const leads = await searchLeads({ product: c.product, count: 12 });
      const saved = await saveLeads(db, c.token, leads);
      return send(200, {
        leads: saved.leads_found,
        searchedAt: saved.leads_searched_at,
        error: leads.length ? null : "The search ran but found nothing right now - free search engines often throttle cloud IPs. Try again in a few minutes.",
      });
    }
    if (cmLeadsRemove && method === "POST") {
      if (!isAdmin) return send(401, { error: "Admin login required" });
      const c = await getCustomerByToken(db, cmLeadsRemove.token);
      if (!c) return send(404, { error: "Customer not found" });
      const body = await readBody(req);
      const kept = (c.leads_found || []).filter((l) => l.id !== body.id);
      const saved = await saveLeads(db, c.token, kept);
      return send(200, { ok: true, leads: saved.leads_found });
    }

    // --- Disable / enable a customer (ADMIN ONLY) ---
    if (url.pathname === "/api/disable" && method === "POST") {
      if (!isAdmin) return send(401, { error: "Admin login required" });
      const body = await readBody(req);
      const c = await setDisabled(db, body.token, body.disabled ? 1 : 0);
      if (!c) return send(404, { error: "Customer not found" });
      return send(200, { ok: true, disabled: c.disabled === 1, token: c.token });
    }

    // --- Register a customer (ADMIN ONLY) ---
    if (url.pathname === "/api/register" && method === "POST") {
      if (!isAdmin) return send(401, { error: "Admin login required" });
      const body = await readBody(req);
      const c = await registerCustomer(db, {
        product: body.product,
        leadFields: Array.isArray(body.leadFields) ? body.leadFields : [body.leadFields].filter(Boolean),
        contactEmail: body.contactEmail,
        persona: body.persona,
      });
      if (body.settings && typeof body.settings === "object") await updateCustomer(db, c.token, { settings: body.settings });
      if (Array.isArray(body.callList)) await setCallList(db, c.token, body.callList);
      const fresh = await getCustomerByToken(db, c.token);
      return send(200, { ok: true, token: fresh.token, machineId: fresh.machine_id, product: fresh.product, settings: fresh.settings, callList: fresh.call_list });
    }

    // --- Record a completed AI call (agent posts this; no login) ---
    if (url.pathname === "/api/call-result" && method === "POST") {
      const body = await readBody(req);
      await logCall(db, {
        customerToken: body.token || null,
        product: body.product,
        transcript: body.transcript,
        score: body.score,
        goodLead: !!body.goodLead,
        escalateToHuman: !!body.escalateToHuman,
        strategies: Array.isArray(body.strategies) ? body.strategies : [],
        summary: body.summary,
      });

      let emailResult = null;
      if (body.goodLead) {
        const owner = await getCustomerByToken(db, body.token);
        const to = owner?.contact_email || body.contactEmail;
        if (to) {
          emailResult = await sendEmail({
            to,
            subject: `New qualified lead: ${body.product || "your service"}`,
            text: `A qualified lead was found.\n\n${body.summary || ""}\n\nFull conversation:\n${String(body.transcript || "").slice(0, 2000)}`,
          });
        }
      }
      return send(200, { ok: true, emailed: emailResult });
    }

    // --- Recent calls (admin only) ---
    if (url.pathname === "/api/calls" && method === "GET") {
      if (!isAdmin) return send(401, { error: "Admin login required" });
      return send(200, { calls: await allCalls(db, 50) });
    }
    if (url.pathname === "/api/call" && method === "GET") {
      if (!isAdmin) return send(401, { error: "Admin login required" });
      const call = await getCallById(db, url.searchParams.get("id"));
      if (!call) return send(404, { error: "Call not found" });
      return send(200, { call });
    }

    // --- Outbox (admin only) ---
    if (url.pathname === "/api/outbox" && method === "GET") {
      if (!isAdmin) return send(401, { error: "Admin login required" });
      return send(200, { outbox: listOutbox() });
    }

    // --- Admin dashboard (login required) ---
    if (url.pathname === "/") {
      if (!isAdmin) return send(200, loginHtml());
      await markStaleOffline(db, STALE_AFTER_MS + 2000);
      const rows = await allCustomers(db);
      const calls = await allCalls(db, 20);
      return send(200, dashboardHtml(rows, calls, listOutbox()));
    }

    // --- Installer download (public) ---
    if (url.pathname === "/download/setup" && method === "GET") {
      try {
        const file = path.join(__dirname, "..", "MagicDialer-Setup.exe");
        const stat = fs.statSync(file);
        res.writeHead(200, {
          "Content-Type": "application/octet-stream",
          "Content-Length": stat.size,
          "Content-Disposition": 'attachment; filename="MagicDialer-Setup.exe"',
          "Access-Control-Allow-Origin": "*",
        });
        fs.createReadStream(file).pipe(res);
      } catch {
        // The exe isn't stored on the host: send the customer to the GitHub release asset.
        res.writeHead(302, { "Location": "https://github.com/shomailasif/magic-dialer/releases/latest/download/MagicDialer-Setup.exe", "Access-Control-Allow-Origin": "*" });
        res.end();
      }
      return;
    }

    return send(404, { error: "Not found" });
  });

  server.listen(port, () => {
    console.log(`[magic-dialer] Platform portal running at http://localhost:${port}`);
  });
  return server;
}

function esc(s) {
  return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function logoHtml(size = 96) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="Magic Dialer logo">
  <defs>
    <linearGradient id="mdHead" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#38BDF8"/>
      <stop offset="1" stop-color="#7C3AED"/>
    </linearGradient>
    <linearGradient id="mdWaveC" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#38BDF8"/>
      <stop offset="1" stop-color="#0EA5E9"/>
    </linearGradient>
    <radialGradient id="mdAura" cx="0.5" cy="0.5" r="0.5">
      <stop offset="0" stop-color="#38BDF8" stop-opacity="0.35"/>
      <stop offset="1" stop-color="#0B1220" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect x="8" y="8" width="496" height="496" rx="92" fill="#0F172A" stroke="#334155" stroke-width="5"/>
  <circle cx="256" cy="272" r="170" fill="url(#mdAura)"/>
  <path d="M 112 210 L 82 272 L 112 334" stroke="url(#mdWaveC)" stroke-width="11" stroke-linecap="round" fill="none" opacity="0.9"/>
  <path d="M 400 210 L 430 272 L 400 334" stroke="url(#mdWaveC)" stroke-width="11" stroke-linecap="round" fill="none" opacity="0.9"/>
  <line x1="256" y1="112" x2="256" y2="170" stroke="#38BDF8" stroke-width="9" stroke-linecap="round"/>
  <circle cx="256" cy="96" r="18" fill="#FBBF24"/>
  <rect x="166" y="156" width="180" height="172" rx="58" fill="url(#mdHead)"/>
  <circle cx="213" cy="231" r="20" fill="#FFFFFF"/><circle cx="299" cy="231" r="20" fill="#FFFFFF"/>
  <ellipse cx="213" cy="233" rx="9" ry="13" fill="#0B1220"/><ellipse cx="299" cy="233" rx="9" ry="13" fill="#0B1220"/>
  <path d="M 224 264 Q 256 288 288 264" fill="none" stroke="#FFFFFF" stroke-width="10" stroke-linecap="round"/>
  <circle cx="146" cy="250" r="9" fill="#38BDF8"/><circle cx="366" cy="250" r="9" fill="#38BDF8"/>
</svg>`;
}

function pageShell(title, body, { bodyClass = "" } = {}) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(title)}</title>
  <style>
    *{box-sizing:border-box}
    body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0b1020;color:#e2e8f0;margin:0;min-height:100vh}
    .btn{display:inline-block;background:linear-gradient(90deg,#4f46e5,#0ea5e9);color:#fff;border:0;padding:9px 14px;border-radius:9px;cursor:pointer;font-weight:600;font-size:13px;text-decoration:none;transition:transform .12s ease,box-shadow .12s ease}
    .btn:hover{transform:translateY(-1px);box-shadow:0 8px 22px -8px rgba(79,70,229,.6)}
    .btn:disabled{opacity:.5;cursor:default;transform:none}
    .btn.ghost{background:rgba(148,163,184,.10);color:#cbd5e1;border:1px solid rgba(148,163,184,.22)}
    .btn.danger{background:linear-gradient(90deg,#dc2626,#ef4444)}
    .badge{display:inline-block;font-size:10.5px;font-weight:700;padding:3px 9px;border-radius:999px;letter-spacing:.3px;text-transform:uppercase}
    .badge.online{background:rgba(16,185,129,.16);color:#34d399}
    .badge.offline{background:rgba(148,163,184,.14);color:#94a3b8}
    .badge.disabled{background:rgba(248,113,113,.14);color:#f87171}
    .badge.voip{background:rgba(139,92,246,.16);color:#c4b5fd}
    .badge.neutral{background:rgba(56,189,248,.14);color:#7dd3fc}
    table{width:100%;border-collapse:collapse}
    th{text-align:left;font-size:10.5px;text-transform:uppercase;letter-spacing:.6px;color:#7c8aa8;font-weight:700;padding:10px 12px;border-bottom:1px solid rgba(148,163,184,.14)}
    td{padding:12px;border-bottom:1px solid rgba(148,163,184,.08);font-size:13px;vertical-align:middle}
    tr:hover td{background:rgba(148,163,184,.045)}
    .card{background:linear-gradient(160deg,#171d38,#10152a);border:1px solid rgba(99,102,241,.22);border-radius:14px}
    .modal{position:fixed;inset:0;background:rgba(4,7,18,.92);display:none;align-items:flex-start;justify-content:center;z-index:50;padding:5vh 20px;overflow:auto}
    .inp,textarea.inp{width:100%;background:#0b1220;border:1px solid #2c3350;color:#e2e8f0;padding:10px 12px;border-radius:9px;font-size:13px;outline:none}
    .inp:focus{border-color:#6366f1}
    label.f{display:block;font-size:11px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;color:#8b98b8;margin:12px 0 5px}
    .mono{font-family:Consolas,'Courier New',monospace}
    .fade{animation:mdFade .35s ease}
    @keyframes mdFade{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}
    a{color:#7dd3fc}
    .nav{font-size:13px;padding:9px 12px;border-radius:9px;color:#a5b0cc;cursor:pointer;display:flex;gap:10px;align-items:center}
    .nav.active{background:linear-gradient(90deg,rgba(79,70,229,.22),rgba(14,165,233,.12));color:#e2e8f0}
    .nav:hover{background:rgba(148,163,184,.08)}
  </style></head><body class="${bodyClass}">${body}</body></html>`;
}

function loginHtml() {
  return pageShell("Magic Dialer - Platform Console", `
  <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px">
    <div style="max-width:1120px;width:100%;display:grid;grid-template-columns:1fr 400px;gap:48px;align-items:center">
      <div style="display:none"></div>
      <div>
        <div class="card fade" style="padding:38px">
          <div style="display:flex;align-items:center;gap:14px;margin-bottom:26px">
            ${logoHtml(52)}
            <div>
              <div style="font-size:20px;font-weight:700;background:linear-gradient(90deg,#a5b4fc,#38bdf8);-webkit-background-clip:text;background-clip:text;color:transparent">Magic Dialer</div>
              <div style="color:#7c8aa8;font-size:13px">Platform Console</div>
            </div>
          </div>
          <form id="f">
            <label class="f" for="p" style="margin-top:0">Admin password</label>
            <input type="password" id="p" class="inp" placeholder="Your console password" autocomplete="current-password" autofocus>
            <button class="btn" type="submit" style="width:100%;margin-top:16px;padding:12px">Sign in to console</button>
            <div class="err" id="err" style="display:none;color:#f87171;font-size:13px;margin-top:12px;text-align:center">Wrong password. Try again.</div>
          </form>
        </div>
      </div>
    </div>
  </div>
  <script>
    document.getElementById('f').addEventListener('submit', async (e) => {
      e.preventDefault();
      const r = await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('p').value})});
      if (r.ok) location.href='/'; else document.getElementById('err').style.display='block';
    });
  </script>`);
}

function jsonSafe(v) {
  return JSON.stringify(v).replace(/</g, "\\u003c");
}

function dashboardHtml(rows, calls = [], outbox = []) {
  const online = rows.filter((c) => c.status === "online" && c.disabled !== 1).length;
  const total = rows.length;
  const disabled = rows.filter((c) => c.disabled === 1).length;
  const qualifiedCalls = calls.filter((c) => c.good_lead === 1).length;
  const avgScore = calls.length ? Math.round((calls.reduce((s, c) => s + (Number(c.score) || 0), 0) / calls.length) * 100) / 100 : 0;
  const leadCount = rows.reduce((s, c) => s + (c.leads_found || []).length, 0);

  const stat = (label, value, accent) => `<div class="card" style="padding:15px 18px;text-align:center">
    <div style="font-size:26px;font-weight:700;color:${accent}">${value}</div>
    <div style="color:#7c8aa8;font-size:11px;margin-top:3px;letter-spacing:.3px">${label}</div></div>`;

  const rowsTr = rows.map((c) => {
    const state = c.disabled === 1 ? "DISABLED" : c.status === "online" ? "ONLINE" : "OFFLINE";
    const cls = c.disabled === 1 ? "badge disabled" : c.status === "online" ? "badge online" : "badge offline";
    const lastSeen = c.last_seen ? new Date(c.last_seen).toLocaleString() : "never";
    const line = c.voip_ready === 1 ? '<span class="badge voip">VOIP</span>' : '<span class="badge neutral">no line</span>';
    const company = c.settings && c.settings.companyName;
    const leads = c.leads_found || [];
    const callsN = (c.call_list || []).length;
    return `<tr class="fade">
      <td>
        <div style="font-weight:600">${esc(c.product || "Untitled customer")}</div>
        <div style="color:#7c8aa8;font-size:11.5px;margin-top:2px">${esc(company || "")} &middot; ${esc(c.persona || "")}</div>
      </td>
      <td><span class="${cls}">${state}</span></td>
      <td>${line}</td>
      <td><span class="badge neutral" data-token="${c.token}" data-action="calllist" style="cursor:pointer">${callsN} numbers</span></td>
      <td><span class="badge neutral" data-token="${c.token}" data-action="leads" style="cursor:pointer">${leads.length} found</span></td>
      <td style="color:#7c8aa8;font-size:12px">${esc(c.contact_email || "-")}</td>
      <td style="color:#7c8aa8;font-size:12px;white-space:nowrap">${lastSeen}</td>
      <td style="white-space:nowrap">
        <button class="btn ghost" data-token="${c.token}" data-action="edit" style="padding:5px 10px;font-size:12px">Edit</button>
        ${c.disabled === 1
          ? `<button class="btn ghost" style="padding:5px 10px;font-size:12px;margin-left:4px;color:#34d399" data-token="${c.token}" data-action="enable">Enable</button>`
          : `<button class="btn ghost danger" style="padding:5px 10px;font-size:12px;margin-left:4px" data-token="${c.token}" data-action="disable">Disable</button>`}
      </td>
    </tr>`;
  }).join("");

  const callsTr = callsHtml(calls);

  const outboxHtml = outbox.length
    ? outbox.map((o) => `<div class="card" style="padding:16px;margin-bottom:10px">
        <div style="color:#7dd3fc;font-size:12px;font-weight:600;margin-bottom:6px">${esc(o.file)}</div>
        <pre class="mono" style="margin:0;color:#cbd5e1;font-size:12px;white-space:pre-wrap;overflow:auto">${esc(o.content)}</pre></div>`).join("")
    : '<div class="card" style="padding:16px;color:#7c8aa8;font-size:13px">No emails out yet.</div>';

  return pageShell("Magic Dialer - Console", `
  <div style="display:flex;min-height:100vh">
    <aside style="width:230px;flex-shrink:0;background:#0d1226;border-right:1px solid rgba(99,102,241,.18);padding:20px 14px;position:sticky;top:0;height:100vh">
      <div style="display:flex;align-items:center;gap:10px;padding:0 6px 18px;border-bottom:1px solid rgba(148,163,184,.12)">
        ${logoHtml(40)}
        <div>
          <div style="font-weight:700;font-size:15px">Magic Dialer</div>
          <div style="color:#7c8aa8;font-size:11px">Platform Console</div>
        </div>
      </div>
      <div style="margin-top:16px;display:flex;flex-direction:column;gap:3px">
        <div class="nav active" data-nav="customers">Customers</div>
        <div class="nav" data-nav="calls">AI calls</div>
        <div class="nav" data-nav="outbox">Email outbox</div>
        <a class="nav" href="/download/setup" style="text-decoration:none">Download installer</a>
      </div>
      <div style="position:absolute;bottom:18px;left:14px;right:14px">
        <button class="btn ghost" id="logout" style="width:100%">Sign out</button>
      </div>
    </aside>

    <main style="flex:1;padding:24px 30px;min-width:0">
      <header style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:10px">
        <div>
          <h1 style="margin:0;font-size:20px;font-weight:700">Command center</h1>
          <div style="color:#7c8aa8;font-size:13px;margin-top:2px">Customers, call lists, AI leads and call records</div>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn" id="addUser">+ New customer</button>
          <button class="btn ghost" id="exportCsv">Export CSV</button>
        </div>
      </header>

      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px">
        ${stat("Customers", total, "#7dd3fc")}
        ${stat("Online", online, "#34d399")}
        ${stat("Disabled", disabled, disabled > 0 ? "#f87171" : "#7c8aa8")}
        ${stat("Qualified calls", qualifiedCalls, "#a5b4fc")}
        ${stat("Leads found", leadCount, "#fbbf24")}
        ${stat("Avg score", avgScore, "#94a3b8")}
      </div>

      <div id="section-customers">
        <div style="display:flex;justify-content:space-between;align-items:baseline;margin:0 0 10px">
          <h2 style="font-size:15px;font-weight:700;color:#c7d2fe;margin:0">Customers</h2>
        </div>
        <div class="card" style="overflow:auto">
          <table>
            <thead><tr><th>Sales form</th><th>Status</th><th>Line</th><th>Call list</th><th>AI leads</th><th>Email</th><th>Last seen</th><th>Actions</th></tr></thead>
            <tbody>${rowsTr || '<tr><td colspan="8" style="color:#7c8aa8">No customers yet - click "New customer" to add one.</td></tr>'}</tbody>
          </table>
        </div>
      </div>

      <div id="section-calls" style="display:none;margin-top:24px">
        <h2 style="font-size:15px;font-weight:700;color:#c7d2fe;margin:0 0 10px">AI calls</h2>
        <div class="card" style="overflow:auto">
          <table>
            <thead><tr><th>Product</th><th>Result</th><th>Score</th><th>Strategies</th><th>Time</th><th></th></tr></thead>
            <tbody>${callsTr}</tbody>
          </table>
        </div>
      </div>

      <div id="section-outbox" style="display:none;margin-top:24px">
        <h2 style="font-size:15px;font-weight:700;color:#c7d2fe;margin:0 0 10px">Email outbox <span style="color:#7c8aa8;font-weight:400;font-size:12px">(if no SMTP configured)</span></h2>
        ${outboxHtml}
      </div>
    </main>
  </div>

  <div id="mEdit" class="modal"></div>
  <div id="mCallList" class="modal"></div>
  <div id="mLeads" class="modal"></div>
  <div id="mTranscript" class="modal"></div>

  <script>
    const CUSTOMERS = ${jsonSafe(rows)};
    const $ = (id) => document.getElementById(id);
    let autoReloadTimer = null;

    function stopAutoReload(){ if(autoReloadTimer){clearTimeout(autoReloadTimer);autoReloadTimer=null;} }
    function scheduleAutoReload(ms){
      stopAutoReload();
      const anyOpen = ["mEdit","mCallList","mLeads","mTranscript"].some(id => $(id).style.display !== 'none') || $('addPanel');
      if (anyOpen) return;
      autoReloadTimer = setTimeout(() => location.reload(), ms || 20000);
    }
    function openModal(id){ stopAutoReload(); $(id).style.display='flex'; }
    function closeModals(){ ["mEdit","mCallList","mLeads","mTranscript"].forEach(id => $(id).style.display='none'); scheduleAutoReload(20000); }
    function cust(token){ return CUSTOMERS.find(c => c.token === token); }

    async function apiFetch(url, opts){
      const r = await fetch(url, Object.assign({headers:{'Content-Type':'application/json'}}, opts||{}));
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || ('HTTP '+r.status));
      return j;
    }

    // --- nav ---
    document.querySelectorAll('.nav[data-nav]').forEach(n => n.addEventListener('click', () => {
      document.querySelectorAll('.nav[data-nav]').forEach(x => x.classList.remove('active'));
      n.classList.add('active');
      ['customers','calls','outbox'].forEach(k => $('section-'+k).style.display = (k === n.dataset.nav ? 'block' : 'none'));
    }));

    // --- add customer ---
    const addBtn = $('addUser');
    const addPanel = document.createElement('div');
    addPanel.id = 'addPanel';
    addPanel.style.display = 'none';
    addPanel.innerHTML = \`<div class="card" style="padding:22px;margin-bottom:22px">
      <div style="font-weight:650;font-size:14px;margin-bottom:4px">New customer account</div>
      <div style="color:#7c8aa8;font-size:12px;margin-bottom:12px">Creates an access key. The customer pastes it into their Magic Dialer setup.</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px">
        <div><label class="f">Sales form - product/service</label><input id="cProduct" class="inp" placeholder="e.g. Heating oil delivery"></div>
        <div><label class="f">Lead info (comma-separated)</label><input id="cFields" class="inp" placeholder="Name, Phone, Address"></div>
        <div><label class="f">Qualified-lead email</label><input id="cEmail" class="inp" placeholder="owner@company.com"></div>
        <div><label class="f">Agent persona / name</label><input id="cPersona" class="inp" placeholder="Sophie"></div>
      </div>
      <div style="margin-top:14px;display:flex;gap:8px;align-items:center">
        <button class="btn" id="createBtn">Create customer</button>
        <button class="btn ghost" id="cancelBtn">Cancel</button>
        <span id="createMsg" style="font-size:13px"></span>
      </div>
      <div id="resultBox" style="display:none;margin-top:16px;background:#0b1220;border:1px solid #2c3350;border-radius:10px;padding:16px">
        <div style="color:#a5b4fc;font-weight:650;margin-bottom:10px">Customer created - give them this access key:</div>
        <div id="resultDetails" class="mono" style="font-size:12px;color:#7dd3fc;line-height:1.8"></div>
        <button class="btn" id="doneBtn" style="margin-top:14px">Done</button>
      </div>
    </div>\`;
    $('section-customers').prepend(addPanel);
    addBtn.addEventListener('click', () => { stopAutoReload(); addPanel.style.display='block'; addPanel.scrollIntoView({behavior:'smooth'}); });
    $('cancelBtn').addEventListener('click', () => { addPanel.style.display='none'; scheduleAutoReload(20000); });
    $('doneBtn').addEventListener('click', () => { addPanel.style.display='none'; scheduleAutoReload(20000); });
    $('createBtn').addEventListener('click', async () => {
      const product = $('cProduct').value.trim();
      if (!product) { $('createMsg').textContent='Enter the sales form product.'; $('createMsg').style.color='#f87171'; return; }
      $('createBtn').disabled = true;
      try {
        const body = { product, leadFields: $('cFields').value.split(',').map(s=>s.trim()).filter(Boolean), contactEmail: $('cEmail').value.trim(), persona: $('cPersona').value.trim() || 'Sophie' };
        const j = await apiFetch('/api/register', {method:'POST', body: JSON.stringify(body)});
        $('resultDetails').innerHTML = 'Portal URL (agent connects here):<br>' + location.origin + '<br><br>Access key (paste into agent):<br>' + j.token;
        $('resultBox').style.display='block';
        $('cProduct').value=''; $('cFields').value=''; $('cEmail').value=''; $('cPersona').value='';
        $('createMsg').textContent='Created - copy the key.'; $('createMsg').style.color='#34d399';
      } catch(e) { $('createMsg').textContent=e.message; $('createMsg').style.color='#f87171'; $('createBtn').disabled=false; }
    });

    // --- actions ---
    document.addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-action], [data-action]');
      if (btn && btn.dataset.action) {
        const a = btn.dataset.action, token = btn.dataset.token;
        if (a === 'disable' || a === 'enable') {
          btn.disabled = true;
          await apiFetch('/api/disable', {method:'POST', body: JSON.stringify({token, disabled: a === 'disable'})});
          location.reload(); return;
        }
        if (a === 'edit') { openEdit(token); return; }
        if (a === 'calllist') { openCallList(token); return; }
        if (a === 'leads') { openLeads(token); return; }
      }
      if (e.target.id === 'logout') { await fetch('/logout',{method:'POST'}); location.href='/'; }
      if (e.target.id === 'exportCsv') { exportCsv(); return; }
      const mc = e.target.closest('#mTranscript button[data-call]');
      if (mc) {
        const j = await apiFetch('/api/call?id=' + mc.dataset.call);
        $('mTranscript').innerHTML = transcriptView(j.call);
        openModal('mTranscript'); return;
      }
      const cc = e.target.closest('#mTranscript button[data-close]');
      if (cc) closeModals();
      // leads add/dismiss
      const la = e.target.closest('[data-leadaction]');
      if (la && la.dataset.token) {
        const token = la.dataset.token, leads = cust(token).leads_found || [];
        const id = la.dataset.id;
        if (la.dataset.leadaction === 'dismiss') {
          await apiFetch('/api/customer/'+token+'/leads/remove', {method:'POST', body: JSON.stringify({id})});
          location.reload(); return;
        }
        if (la.dataset.leadaction === 'call') {
          const lead = leads.find(l => l.id === id);
          if (!lead) return;
          const current = cust(token).call_list || [];
          current.push((lead.company || lead.title) + ' : (need phone) ' + lead.source);
          await apiFetch('/api/customer/'+token+'/calllist', {method:'POST', body: JSON.stringify({numbers: current})});
          btn.disabled = true; btn.textContent = 'added';
        }
      }
    });

    function exportCsv(){
      let csv = 'product,status,contact_email,persona,company_call_list,leads_found\n';
      for (const c of CUSTOMERS) {
        csv += [c.product, c.status, c.contact_email, c.persona, (c.call_list||[]).join('|'), (c.leads_found||[]).map(l=>l.company).join('|')].map(v => '"' + String(v==null?'':v).replace(/"/g,'""') + '"').join(',') + '\n';
      }
      const a = document.createElement('a');
      a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
      a.download = 'magic-dialer-customers.csv';
      a.click();
    }

    function openEdit(token){
      const c = cust(token); if (!c) return;
      const s = c.settings || {};
      $('mEdit').innerHTML = \`<div class="card" style="width:640px;max-width:100%;padding:24px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <div style="font-size:15px;font-weight:700">Edit sales form</div>
          <button class="btn ghost" data-close="1" style="padding:5px 11px">Close</button>
        </div>
        <div style="color:#7c8aa8;font-size:12px;margin-bottom:14px">Changes are pushed to the customer's PC on its next heartbeat.</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 16px">
          <div style="grid-column:1 / -1"><label class="f">Product / service</label><input id="eProduct" class="inp" value="\${esc(c.product||'')}"></div>
          <div style="grid-column:1 / -1"><label class="f">Lead info needed (comma-separated)</label><input id="eFields" class="inp" value="\${esc((c.lead_fields||[]).join(', '))}"></div>
          <div><label class="f">Qualified-lead email</label><input id="eEmail" class="inp" value="\${esc(c.contact_email||'')}"></div>
          <div><label class="f">Agent persona / name</label><input id="ePersona" class="inp" value="\${esc(c.persona||'')}"></div>
          <div><label class="f">Company name (agent intro)</label><input id="eCompany" class="inp" value="\${esc(s.companyName||'')}"></div>
          <div><label class="f">Service call-back number</label><input id="eCallback" class="inp" value="\${esc(s.callbackNumber||'')}"></div>
          <div><label class="f">Calls back within (e.g. 30 minutes)</label><input id="eCallbackIn" class="inp" value="\${esc(s.callbackIn||'')}"></div>
        </div>
        <label style="display:flex;gap:8px;align-items:center;margin-top:14px;font-size:13px;color:#cbd5e1">
          <input type="checkbox" id="eSearch" \${s.searchEnabled !== false ? 'checked' : ''}> Let Magic Dialer search the internet for leads on its own
        </label>
        <div style="display:flex;gap:8px;margin-top:18px">
          <button class="btn" id="eSave">Save changes</button>
          <button class="btn ghost" data-close="1">Cancel</button>
        </div>
      </div>\`;
      openModal('mEdit');
      setTimeout(() => {
        const sv = $.extend ? null : null;
        const closeBtns = $('mEdit').querySelectorAll('[data-close]');
        closeBtns.forEach(b => b.addEventListener('click', closeModals));
        $('eSave').addEventListener('click', async () => {
          $('eSave').disabled = true;
          try {
            await apiFetch('/api/customer/'+token, {method:'PATCH', body: JSON.stringify({
              product: $('eProduct').value, leadFields: $('eFields').value.split(',').map(x=>x.trim()).filter(Boolean),
              contactEmail: $('eEmail').value, persona: $('ePersona').value,
              settings: { companyName: $('eCompany').value, callbackNumber: $('eCallback').value, callbackIn: $('eCallbackIn').value, searchEnabled: $('eSearch').checked }
            })});
            location.reload();
          } catch(e) { alert(e.message); $('eSave').disabled = false; }
        });
      }, 0);
    }

    function openCallList(token){
      const c = cust(token);
      const list = (c.call_list || []).join('\\n');
      $('mCallList').innerHTML = \`<div class="card" style="width:620px;max-width:100%;padding:24px">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div style="font-size:15px;font-weight:700">Call list</div>
          <button class="btn ghost" data-close="1" style="padding:5px 11px">Close</button>
        </div>
        <div style="color:#7c8aa8;font-size:12px;margin:6px 0 12px">One number per line. The AI works this list when its phone line is connected.</div>
        <textarea id="clText" class="inp" rows="10" placeholder="+1 555 0100">\${esc(list)}</textarea>
        <div style="display:flex;gap:8px;margin-top:14px">
          <button class="btn" id="clSave">Save list</button>
          <button class="btn ghost" data-close="1">Cancel</button>
        </div>
      </div>\`;
      openModal('mCallList');
      setTimeout(() => {
        $('mCallList').querySelectorAll('[data-close]').forEach(b => b.addEventListener('click', closeModals));
        $('clSave').addEventListener('click', async () => {
          $('clSave').disabled = true;
          const numbers = $('clText').value.split(/[\\r\\n,]+/).map(s=>s.trim()).filter(Boolean);
          await apiFetch('/api/customer/'+token+'/calllist', {method:'POST', body: JSON.stringify({numbers})});
          location.reload();
        });
      }, 0);
    }

    function openLeads(token){
      const c = cust(token);
      const leads = c.leads_found || [];
      const rows = leads.map(l => \`<div class="card" style="padding:14px;margin-bottom:10px">
        <div style="font-weight:600;font-size:13.5px">\${esc(l.company||l.title)}</div>
        <div class="mono" style="color:#7c8aa8;font-size:11.5px;margin:3px 0">\${esc(l.source||'')}</div>
        <div style="color:#a5b4fc;font-size:12.5px;margin:4px 0">\${esc(l.snippet||'')}</div>
        <div style="display:flex;gap:8px;margin-top:8px">
          <button class="btn" data-leadaction="call" data-token="\${token}" data-id="\${esc(l.id)}" style="padding:6px 12px;font-size:12px">Add to call list</button>
          <button class="btn ghost" data-leadaction="dismiss" data-token="\${token}" data-id="\${esc(l.id)}" style="padding:6px 12px;font-size:12px">Dismiss</button>
        </div>
      </div>\`).join('');
      $('mLeads').innerHTML = \`<div class="card" style="width:680px;max-width:100%;padding:24px">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div style="font-size:15px;font-weight:700">Internet lead finder</div>
          <button class="btn ghost" data-close="1" style="padding:5px 11px">Close</button>
        </div>
        <div style="color:#7c8aa8;font-size:12px;margin:6px 0 14px">Searches the web for companies tied to "\${esc(c.product||'')}" and stores them here. Review, then push the good ones into the call list.</div>
        <div style="margin-bottom:14px">
          <button class="btn" id="leadSearchBtn">\${leads.length ? 'Search the internet again' : 'Search the internet for leads'}</button>
          <span id="leadStatus" style="font-size:13px;margin-left:10px"></span>
        </div>
        <div id="leadRows">\${rows || '<div style="color:#7c8aa8;font-size:13px">No leads found yet.</div>'}</div>
      </div>\`;
      openModal('mLeads');
      setTimeout(() => {
        $('mLeads').querySelectorAll('[data-close]').forEach(b => b.addEventListener('click', closeModals));
        $('leadSearchBtn').addEventListener('click', async () => {
          const b = $('leadSearchBtn'); b.disabled = true; $('leadStatus').textContent = 'Searching the web...';
          try {
            const j = await apiFetch('/api/customer/'+token+'/leads/search', {method:'POST', body: '{}'});
            if (j.error) { $('leadStatus').textContent = j.error; $('leadStatus').style.color='#f87171'; }
            else { $('leadStatus').textContent = j.leads.length + ' leads found.'; $('leadStatus').style.color='#34d399'; location.reload(); }
          } catch(e) { $('leadStatus').textContent = e.message; $('leadStatus').style.color='#f87171'; }
          b.disabled = false;
        });
      }, 0);
    }

    function transcriptView(call){
      let lines = [];
      try { const arr = JSON.parse(call.transcript); if (Array.isArray(arr)) lines = arr.map(x => (x.role==='agent'?'AI : ':'LEAD: ')+x.text); } catch {}
      if (!lines.length) lines = String(call.transcript||'').split('\\n');
      return \`<div class="card" style="width:720px;max-width:100%;padding:0;display:flex;flex-direction:column;max-height:86vh;overflow:hidden">
        <div style="display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid rgba(99,102,241,.2)">
          <span style="font-weight:650">\${esc(call.product||'Call')} - score \${call.score}</span>
          <button class="btn ghost" data-close="1">Close</button>
        </div>
        <pre class="mono" style="margin:0;padding:18px 20px;overflow:auto;color:#e2e8f0;font-size:12.5px;line-height:1.7;white-space:pre-wrap;flex:1">\${esc(lines.join('\\n'))}</pre>
      </div>\`;
    }

    // global close handlers for data-close buttons inside modals
    document.addEventListener('click', (e) => {
      if (e.target.closest('[data-close]')) closeModals();
    });

    scheduleAutoReload(20000);
  </script>`);
}

function callsHtml(calls) {
  if (!calls.length) return '<tr><td colspan="6" style="color:#7c8aa8">No calls yet.</td></tr>';
  return calls.map((c) => {
    const ok = c.good_lead === 1;
    let strategies = [];
    if (c.strategies) { try { strategies = JSON.parse(c.strategies); } catch {} }
    const chips = strategies.slice(0, 3).map((k) =>
      `<span class="badge neutral">${esc(k.replace(/_/g, " "))}</span>`
    ).join(" ");
    return `<tr>
      <td style="font-weight:600">${esc(c.product || "call")}</td>
      <td><span class="${ok ? "badge online" : "badge offline"}">${ok ? "QUALIFIED" : c.escalated === 1 ? "ESCALATED" : "no lead"}</span></td>
      <td>${c.score}</td>
      <td><div style="display:flex;gap:6px;flex-wrap:wrap">${chips || '<span style="color:#7c8aa8;font-size:12px">-</span>'}</div></td>
      <td style="color:#7c8aa8;font-size:12px;white-space:nowrap">${new Date(c.created_at).toLocaleString()}</td>
      <td><button class="btn ghost" data-call="${c.id}" style="padding:5px 10px;font-size:12px">Transcript</button></td>
    </tr>`;
  }).join("");
}

// Allow running directly: node server.js [port]
if (require.main === module) {
  const port = Number(process.env.AUTODIAL_PORT || process.env.PORT || process.argv[2] || 8787);
  start({ port }).catch((err) => {
    console.error("[magic-dialer] failed to start:", err);
    process.exit(1);
  });
}

module.exports = { start };