const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { openDb, registerCustomer, processHeartbeat, setDisabled, markStaleOffline, allCustomers, getCustomerByToken, logCall, allCalls } = require("./db");
const { HEARTBEAT_INTERVAL_MS, STALE_AFTER_MS, heartbeatResponse } = require("../shared/protocol");
const { sendEmail, listOutbox } = require("./mailer");
const { issueSession, verifySession, sessionFromCookieHeader, checkPassword, adminPassword } = require("./auth");

/**
 * Magic Dialer — admin cloud portal.
 *
 * A small dependency-free HTTP server the admin can host anywhere (free
 * cloud host). It keeps the list of customer PCs, their health, and the
 * disable state. The agent PC ====heartbeat===> portal on /api/heartbeat;
 * the admin watches on "/" and can disable any customer.
 */

async function start({ dbPath = path.join(__dirname, "portal.db"), port = 8787, adminPassword } = {}) {
  const db = await openDb(dbPath);

  // Periodically mark customers offline who stopped reporting.
  setInterval(() => { markStaleOffline(db, STALE_AFTER_MS + 2000); }, HEARTBEAT_INTERVAL_MS);

  async function readBody(req) {
    let data = "";
    for await (const chunk of req) data += chunk;
    try {
      return JSON.parse(data || "{}");
    } catch {
      return {};
    }
  }

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

    // Whether the current request has a valid admin session.
    const isAdmin = verifySession(sessionFromCookieHeader(req.headers.cookie));

    // --- Admin login page + handler ---
    if (url.pathname === "/login" && method === "GET") {
      return send(200, loginHtml());
    }
    if (url.pathname === "/login" && method === "POST") {
      const body = await readBody(req);
      if (checkPassword(body.password, adminPassword)) {
        const cookie = `session=${issueSession()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`;
        return send(200, { ok: true }, { "Set-Cookie": cookie });
      }
      return send(401, { error: "Wrong password" });
    }
    if (url.pathname === "/logout" && method === "POST") {
      return send(200, { ok: true }, { "Set-Cookie": "session=; Path=/; HttpOnly; Max-Age=0" });
    }

    // --- Heartbeat from a customer's PC (no login — the agent must work) ---
    if (url.pathname === "/api/heartbeat" && method === "POST") {
      const body = await readBody(req);
      const out = await processHeartbeat(db, { token: body.token });
      return send(200, heartbeatResponse({
        ok: out.ok,
        disabled: out.disabled,
        config: out.config,
        reason: out.reason,
      }));
    }

    // --- Disable / enable a customer (ADMIN ONLY) ---
    if (url.pathname === "/api/disable" && method === "POST") {
      if (!isAdmin) return send(401, { error: "Admin login required" });
      const body = await readBody(req);
      const c = await setDisabled(db, body.token, body.disabled ? 1 : 0);
      if (!c) return send(404, { error: "Customer not found" });
      return send(200, { ok: true, disabled: c.disabled === 1, token: c.token });
    }

    // --- Register a customer (admin flow; keep open for setup, but admin login is safer) ---
    if (url.pathname === "/api/register" && method === "POST") {
      if (!isAdmin) return send(401, { error: "Admin login required" });
      const body = await readBody(req);
      const c = await registerCustomer(db, {
        product: body.product,
        leadFields: Array.isArray(body.leadFields) ? body.leadFields : [body.leadFields].filter(Boolean),
        contactEmail: body.contactEmail,
        persona: body.persona,
      });
      return send(200, { ok: true, token: c.token, machineId: c.machineId, product: c.product });
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
      const calls = await allCalls(db, 10);
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
        return send(404, { error: "Installer not available on this instance - use the GitHub release." });
      }
      return;
    }

    return send(404, { error: "Not found" });
  });

  server.listen(port, () => {
    console.log(`[magic-dialer] Admin cloud portal running at http://localhost:${port}`);
  });
  return server;
}

function esc(s) {
  return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// Inline "Magic Dialer" logo — the robot head with sound waves (matches the
// desktop Agent Cockpit and installer icon). Self-contained SVG, no external
// image, works on any free host.
function logoHtml(size = 96) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="Magic Dialer logo">
  <defs>
    <linearGradient id="mdHead" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#22D3EE"/>
      <stop offset="1" stop-color="#8B5CF6"/>
    </linearGradient>
    <linearGradient id="mdWaveC" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#22D3EE"/>
      <stop offset="1" stop-color="#0EA5E9"/>
    </linearGradient>
    <linearGradient id="mdWaveV" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#8B5CF6"/>
      <stop offset="1" stop-color="#7C3AED"/>
    </linearGradient>
    <radialGradient id="mdAura" cx="0.5" cy="0.5" r="0.5">
      <stop offset="0" stop-color="#22D3EE" stop-opacity="0.5"/>
      <stop offset="0.55" stop-color="#8B5CF6" stop-opacity="0.18"/>
      <stop offset="1" stop-color="#0B1220" stop-opacity="0"/>
    </radialGradient>
    <filter id="mdGlow" x="-80%" y="-80%" width="260%" height="260%">
      <feGaussianBlur stdDeviation="7" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="mdSoft" x="-60%" y="-60%" width="220%" height="220%">
      <feGaussianBlur stdDeviation="3" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  </defs>
  <rect x="8" y="8" width="496" height="496" rx="92" fill="#0F172A" stroke="#334155" stroke-width="5"/>
  <circle cx="256" cy="272" r="175" fill="url(#mdAura)"/>
  <path d="M 88 208 Q 58 272 88 336" stroke="url(#mdWaveC)" stroke-width="11" stroke-linecap="round" fill="none" opacity="0.95"/>
  <path d="M 66 188 Q 26 272 66 356" stroke="url(#mdWaveV)" stroke-width="11" stroke-linecap="round" fill="none" opacity="0.6"/>
  <path d="M 424 208 Q 454 272 424 336" stroke="url(#mdWaveC)" stroke-width="11" stroke-linecap="round" fill="none" opacity="0.95"/>
  <path d="M 446 188 Q 486 272 446 356" stroke="url(#mdWaveV)" stroke-width="11" stroke-linecap="round" fill="none" opacity="0.6"/>
  <line x1="256" y1="112" x2="256" y2="170" stroke="#22D3EE" stroke-width="9" stroke-linecap="round"/>
  <circle cx="256" cy="96" r="19" fill="#FBBF24" filter="url(#mdGlow)"/>
  <circle cx="256" cy="96" r="7" fill="#FFFFFF" opacity="0.9"/>
  <rect x="166" y="156" width="180" height="172" rx="58" fill="url(#mdHead)" filter="url(#mdGlow)"/>
  <rect x="172" y="162" width="168" height="160" rx="52" fill="none" stroke="#FFFFFF" stroke-opacity="0.25" stroke-width="3"/>
  <circle cx="213" cy="231" r="20" fill="#FFFFFF" filter="url(#mdSoft)"/>
  <circle cx="299" cy="231" r="20" fill="#FFFFFF" filter="url(#mdSoft)"/>
  <ellipse cx="213" cy="231" rx="9" ry="13" fill="#0B1220"/>
  <ellipse cx="299" cy="231" rx="9" ry="13" fill="#0B1220"/>
  <circle cx="299" cy="225" r="3" fill="#FFFFFF" opacity="0.85"/>
  <circle cx="213" cy="225" r="3" fill="#FFFFFF" opacity="0.85"/>
  <path d="M 224 264 Q 256 288 288 264" fill="none" stroke="#FFFFFF" stroke-width="10" stroke-linecap="round"/>
  <circle cx="146" cy="250" r="9" fill="#22D3EE" filter="url(#mdSoft)"/>
  <circle cx="366" cy="250" r="9" fill="#22D3EE" filter="url(#mdSoft)"/>
  <circle cx="146" cy="250" r="3" fill="#FFFFFF" opacity="0.9"/>
  <circle cx="366" cy="250" r="3" fill="#FFFFFF" opacity="0.9"/>
</svg>`;
}

function pageShell(title, body, { bodyClass = "bg" } = {}) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(title)}</title>
  <style>
    *{box-sizing:border-box}
    body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#070a14;color:#e2e8f0;margin:0;min-height:100vh}
    .bg{background:
      radial-gradient(1100px 500px at 15% -10%, rgba(139,92,246,.16), transparent 60%),
      radial-gradient(1000px 500px at 100% 0%, rgba(6,182,212,.14), transparent 55%),
      radial-gradient(900px 600px at 50% 120%, rgba(99,102,241,.10), transparent 60%),
      #070a14}
    .card{background:linear-gradient(160deg,rgba(30,27,75,.72),rgba(15,23,42,.85));border:1px solid rgba(139,92,246,.25);border-radius:18px;backdrop-filter:blur(8px);box-shadow:0 20px 60px -20px rgba(0,0,0,.7)}
    .btn{background:linear-gradient(90deg,#7c3aed,#06b6d4);color:#fff;border:0;padding:11px 16px;border-radius:12px;cursor:pointer;font-weight:600;font-size:14px;transition:transform .12s ease,box-shadow .12s ease}
    .btn:hover{transform:translateY(-1px);box-shadow:0 8px 22px -8px rgba(124,58,237,.7)}
    .btn:disabled{opacity:.5;cursor:default;transform:none}
    .btn.ghost{background:rgba(148,163,184,.12);color:#cbd5e1;border:1px solid rgba(148,163,184,.25)}
    .btn.danger{background:linear-gradient(90deg,#dc2626,#f43f5e)}
    .badge{font-size:11px;font-weight:700;padding:3px 10px;border-radius:999px;letter-spacing:.4px;text-transform:uppercase}
    .badge.online{background:linear-gradient(90deg,#059669,#10b981);color:#fff}
    .badge.offline{background:#334155;color:#cbd5e1}
    .badge.disabled{background:#475569;color:#e2e8f0}
    .badge.voip{background:linear-gradient(90deg,#7c3aed,#a855f7);color:#fff}
    .fade{animation:mdFade .5s ease}
    @keyframes mdFade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
  </style></head><body class="${bodyClass}">${body}</body></html>`;
}

function loginHtml() {
  return pageShell("Magic Dialer — Admin Sign in", `
  <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px">
    <div class="card" style="width:360px;max-width:100%;padding:34px">
      <div style="text-align:center;margin-bottom:22px">
        <div style="display:inline-flex">${logoHtml(86)}</div>
        <h1 style="margin:14px 0 2px;font-size:26px;letter-spacing:.5px;background:linear-gradient(90deg,#a78bfa,#22d3ee);-webkit-background-clip:text;background-clip:text;color:transparent">Magic Dialer</h1>
        <div style="color:#94a3b8;font-size:13px">Cloud control center · sign in to manage</div>
      </div>
      <form id="f">
        <input type="password" id="p" placeholder="Admin password" autocomplete="current-password" autofocus
          style="width:100%;background:#0b1220;border:1px solid #312e81;color:#e2e8f0;padding:13px;border-radius:12px;font-size:14px;margin-bottom:14px;outline:none">
        <button class="btn" type="submit" style="width:100%">Sign in</button>
        <div class="err" id="err" style="display:none;color:#f87171;font-size:13px;margin-top:12px;text-align:center">Wrong password. Try again.</div>
      </form>
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

function dashboardHtml(rows, calls = [], outbox = []) {
  const online = rows.filter((c) => c.status === "online" && c.disabled !== 1).length;
  const total = rows.length;
  const disabled = rows.filter((c) => c.disabled === 1).length;

  const cards = rows.map((c) => {
    const state = c.disabled === 1 ? "DISABLED" : c.status === "online" ? "ONLINE" : "OFFLINE";
    const cls = c.disabled === 1 ? "badge disabled" : c.status === "online" ? "badge online" : "badge offline";
    const lastSeen = c.last_seen ? new Date(c.last_seen).toLocaleString() : "never";
    const voip = c.voip_ready === 1
      ? '<span class="badge voip">VOIP ready</span>'
      : '<span class="badge offline" style="background:#1e293b;color:#94a3b8">no call line</span>';
    return `
      <div class="card fade" data-token="${c.token}" style="padding:18px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
          <span style="font-weight:650;font-size:15px">${esc(c.product || "Untitled customer")}</span>
          <span class="${cls}">${state}</span>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
          <span style="color:#94a3b8;font-size:12px">Call line</span> ${voip}
        </div>
        <div style="font-size:12px;color:#94a3b8;line-height:1.7;margin-bottom:14px">
          <div>Email: ${esc(c.contact_email || "—")}</div>
          <div>Agent: ${esc(c.persona || "—")}</div>
          <div>Lead info: ${esc((safeParse(c.lead_fields) || []).join(", ") || "—")}</div>
          <div>Last heartbeat: ${lastSeen}</div>
        </div>
        <div style="display:flex;gap:8px">
          ${c.disabled === 1
            ? `<button class="btn ghost" data-action="enable" data-token="${c.token}" style="flex:1">Enable</button>`
            : `<button class="btn ghost" data-action="disable" data-token="${c.token}" style="flex:1">Disable</button>`}
        </div>
      </div>`;
  }).join("");

  const stat = (label, value, accent) => `<div class="card" style="padding:16px;text-align:center">
    <div style="font-size:30px;font-weight:700;color:${accent}">${value}</div>
    <div style="color:#94a3b8;font-size:12px;margin-top:2px">${label}</div></div>`;

  return pageShell("Magic Dialer — Command Center", `
  <div style="max-width:1200px;margin:0 auto;padding:24px">
    <header style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:22px">
      <div style="display:flex;align-items:center;gap:14px">
        ${logoHtml(54)}
        <div>
          <div style="font-size:22px;font-weight:700;letter-spacing:.5px;background:linear-gradient(90deg,#a78bfa,#22d3ee);-webkit-background-clip:text;background-clip:text;color:transparent">Magic Dialer</div>
          <div style="color:#94a3b8;font-size:12px">Command center · customer health &amp; remote control</div>
        </div>
      </div>
      <div style="display:flex;gap:8px">
        <button class="btn" id="addUser" style="padding:11px 18px">+ New user</button>
        <button class="btn ghost" id="logout">Sign out</button>
      </div>
    </header>

    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:24px">
      ${stat("Customers", total, "#22d3ee")}
      ${stat("Online", online, "#10b981")}
      ${stat("Disabled", disabled, disabled > 0 ? "#f43f5e" : "#475569")}
    </div>

    <div id="addPanel" style="display:none;margin-bottom:24px">
      <div class="card" style="padding:20px">
        <div style="font-size:16px;font-weight:650;margin-bottom:4px">Add a new customer</div>
        <div style="color:#94a3b8;font-size:12px;margin-bottom:16px">Create an account for a customer. You'll get a key to pass to them — the Magic Dialer agent on their PC uses it to connect.</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px">
          <input id="cProduct" placeholder="What do they sell? e.g. Premium solar panels" style="background:#0b1220;border:1px solid #312e81;color:#e2e8f0;padding:12px;border-radius:12px;font-size:14px;outline:none">
          <input id="cFields" placeholder="Lead info needed, comma-separated (name, phone, budget)" style="background:#0b1220;border:1px solid #312e81;color:#e2e8f0;padding:12px;border-radius:12px;font-size:14px;outline:none">
          <input id="cEmail" placeholder="Email for qualified leads" style="background:#0b1220;border:1px solid #312e81;color:#e2e8f0;padding:12px;border-radius:12px;font-size:14px;outline:none">
          <input id="cPersona" placeholder="Agent persona (optional)" style="background:#0b1220;border:1px solid #312e81;color:#e2e8f0;padding:12px;border-radius:12px;font-size:14px;outline:none">
        </div>
        <div style="margin-top:14px;display:flex;gap:8px;align-items:center">
          <button class="btn" id="createBtn">Create customer</button>
          <button class="btn ghost" id="cancelBtn">Cancel</button>
          <span id="createMsg" style="font-size:13px"></span>
        </div>
        <div id="resultBox" style="display:none;margin-top:16px;background:#0b1220;border:1px solid #312e81;border-radius:12px;padding:16px">
          <div style="color:#a78bfa;font-weight:650;margin-bottom:10px">Customer created — give them this key:</div>
          <div id="resultDetails" style="font-size:12px;color:#94a3b8;line-height:1.8"></div>
          <button class="btn" id="doneBtn" style="margin-top:14px">Done</button>
        </div>
      </div>
    </div>

    <h2 style="font-size:16px;font-weight:650;margin:0 0 12px;color:#c7d2fe">Customers</h2>
    <div class="grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px">
      ${cards || '<div class="card fade" style="padding:20px;color:#94a3b8">No customers yet. Click "New user" to add your first one.</div>'}
    </div>

    <h2 style="font-size:16px;font-weight:650;margin:26px 0 12px;color:#c7d2fe">Recent AI calls</h2>
    <div class="grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px">${callsHtml(calls)}</div>

    <h2 style="font-size:16px;font-weight:650;margin:26px 0 12px;color:#c7d2fe">Email outbox <span style="color:#94a3b8;font-weight:400;font-size:12px">(if no SMTP configured)</span></h2>
    <pre style="background:#0b1220;border:1px solid #1e293b;padding:16px;border-radius:12px;color:#a5f3fc;font-size:12px;white-space:pre-wrap;overflow:auto">${outbox.length ? outbox.map(o => `— ${esc(o.file)}\n${esc(o.content)}`).join("\n\n") : "No emails out yet."}</pre>
  </div>
  <script>
    const $ = (id) => document.getElementById(id);
    let autoReloadTimer = null;
    // Auto-refresh the dashboard, but NEVER while the add-user form is open
    // (otherwise a reload would wipe what you're typing). Re-schedules after
    // the panel closes. Panels that should NOT trigger a refresh: also the
    // result box stays until the user clicks Done.
    function scheduleAutoReload(ms) {
      if (autoReloadTimer) { clearTimeout(autoReloadTimer); autoReloadTimer = null; }
      if ($('addPanel').style.display !== 'none') return; // form open -> no auto reload
      autoReloadTimer = setTimeout(() => { location.reload(); }, ms || 20000);
    }
    function stopAutoReload() {
      if (autoReloadTimer) { clearTimeout(autoReloadTimer); autoReloadTimer = null; }
    }

    function openAddPanel() {
      stopAutoReload();
      $('addPanel').style.display = 'block';
      $('resultBox').style.display = 'none';
      $('createMsg').textContent = '';
      $('createBtn').disabled = false;
      $('addPanel').scrollIntoView({ behavior: 'smooth' });
    }
    function closeAddPanel() {
      $('addPanel').style.display = 'none';
      $('resultBox').style.display = 'none';
      $('cancelBtn').style.display = '';
      $('createMsg').textContent = '';
      scheduleAutoReload(20000);
    }

    document.addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-action]');
      if (btn) {
        btn.disabled = true;
        const body = { token: btn.dataset.token, disabled: btn.dataset.action === 'disable' };
        await fetch('/api/disable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        location.reload(); return;
      }
      if (e.target.id === 'logout') { await fetch('/logout',{method:'POST'}); location.href='/'; }
      if (e.target.id === 'addUser') { openAddPanel(); }
      if (e.target.id === 'cancelBtn') { closeAddPanel(); }
      if (e.target.id === 'doneBtn') { closeAddPanel(); }
      if (e.target.id === 'createBtn') {
        const product = $('cProduct').value.trim();
        if (!product) { $('createMsg').textContent='Please enter what they sell.'; $('createMsg').style.color='#f87171'; return; }
        $('createBtn').disabled = true;
        const body = {
          product,
          leadFields: $('cFields').value.split(',').map(s=>s.trim()).filter(Boolean),
          contactEmail: $('cEmail').value.trim(),
          persona: $('cPersona').value.trim() || 'High-energy, friendly assistant'
        };
        const r = await fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        const j = await r.json();
        if (r.ok) {
          const portal = location.origin;
          $('resultDetails').innerHTML =
            'Portal URL (agent connects here):<br><code style="color:#a5f3fc">' + portal + '</code><br><br>' +
            'Access key (paste into agent):<br><code style="color:#a5f3fc">' + j.token + '</code><br><br>' +
            'Machine ID:<br><code style="color:#94a3b8">' + j.machineId + '</code>';
          $('resultBox').style.display='block';
          $('cancelBtn').style.display='none';
          $('cProduct').value=''; $('cFields').value=''; $('cEmail').value=''; $('cPersona').value='';
          $('createMsg').textContent='Created ✓ — copy the key, then click Done.'; $('createMsg').style.color='#10b981';
        } else {
          $('createMsg').textContent=j.error||'Error'; $('createMsg').style.color='#f87171';
          $('createBtn').disabled=false;
        }
      }
    });
    scheduleAutoReload(20000);
  </script>`);
}

function callsHtml(calls) {
  if (!calls.length) return '<div class="card fade" style="padding:18px;color:#94a3b8">No calls yet.</div>';
  return calls.map((c) => {
    const ok = c.good_lead === 1;
    return `<div class="card fade" style="padding:16px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <span style="font-weight:600">${esc(c.product || "call")}</span>
        <span class="${ok ? "badge online" : "badge offline"}">${ok ? "QUALIFIED" : c.escalated === 1 ? "ESCALATED" : "no lead"}</span>
      </div>
      <div style="font-size:12px;color:#94a3b8;line-height:1.6">Score: ${c.score}<br>${esc(String(c.summary || "").slice(0, 160))}</div>
    </div>`;
  }).join("");
}

function safeParse(s) {
  if (!s) return [];
  try { const v = JSON.parse(s); return Array.isArray(v) ? v : []; } catch { return []; }
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
