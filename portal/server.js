const http = require("node:http");
const path = require("node:path");
const { openDb, registerCustomer, processHeartbeat, setDisabled, markStaleOffline, allCustomers, getCustomerByToken, logCall, allCalls } = require("./db");
const { HEARTBEAT_INTERVAL_MS, STALE_AFTER_MS, heartbeatResponse } = require("../shared/protocol");
const { sendEmail, listOutbox } = require("./mailer");
const { issueSession, verifySession, sessionFromCookieHeader, checkPassword, adminPassword } = require("./auth");

/**
 * Admin cloud portal.
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

    return send(404, { error: "Not found" });
  });

  server.listen(port, () => {
    console.log(`[portal] Admin cloud portal running at http://localhost:${port}`);
  });
  return server;
}

function esc(s) {
  return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function loginHtml() {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Login — AutoDial</title>
  <style>
    body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
    .box{background:#1e293b;border:1px solid #334155;border-radius:14px;padding:28px;width:320px}
    h1{font-size:20px;margin:0 0 4px}
    .sub{color:#94a3b8;font-size:13px;margin-bottom:20px}
    input{width:100%;box-sizing:border-box;background:#0b1220;border:1px solid #334155;color:#e2e8f0;padding:10px;border-radius:8px;margin-bottom:14px;font-size:14px}
    button{width:100%;background:#2563eb;color:#fff;border:0;padding:11px;border-radius:8px;cursor:pointer;font-weight:600;font-size:14px}
    .err{color:#f87171;font-size:13px;margin-top:10px}
  </style></head><body>
  <div class="box">
    <h1>AutoDial Admin</h1>
    <div class="sub">Sign in to manage customers</div>
    <form id="f">
      <input type="password" id="p" placeholder="Admin password" autofocus>
      <button type="submit">Sign in</button>
      <div class="err" id="err" style="display:none">Wrong password. Try again.</div>
    </form>
  </div>
  <script>
    document.getElementById('f').addEventListener('submit', async (e) => {
      e.preventDefault();
      const r = await fetch('/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ password: document.getElementById('p').value }) });
      if (r.ok) location.href = '/';
      else document.getElementById('err').style.display = 'block';
    });
  </script>
  </body></html>`;
}

function dashboardHtml(rows, calls = [], outbox = []) {
  const cards = rows.map((c) => {
    const state = c.disabled === 1 ? "DISABLED" : c.status === "online" ? "ONLINE" : "OFFLINE";
    const cls = c.disabled === 1 ? "badge disabled" : c.status === "online" ? "badge online" : "badge offline";
    const lastSeen = c.last_seen ? new Date(c.last_seen).toLocaleString() : "never";
    const voip = c.voip_ready === 1
      ? '<span class="badge online" style="background:#7c3aed">VOIP ready</span>'
      : '<span class="badge offline" style="background:#475569">no call line</span>';
    return `
      <div class="card" data-token="${c.token}">
        <div class="row">
          <span class="machine">${esc(c.product || "Untitled customer")}</span>
          <span class="${cls}">${state}</span>
        </div>
        <div class="row">
          <span style="color:#94a3b8;font-size:12px">Call line:</span> ${voip}
        </div>
        <div class="meta">
          <div>Email: ${esc(c.contact_email || "—")}</div>
          <div>Agent: ${esc(c.persona || "—")}</div>
          <div>Lead info needed: ${esc((safeParse(c.lead_fields) || []).join(", ") || "—")}</div>
          <div>Last heartbeat: ${lastSeen}</div>
        </div>
        <div class="row">
          ${c.disabled === 1
            ? `<button class="btn" data-action="enable" data-token="${c.token}">Enable</button>`
            : `<button class="btn danger" data-action="disable" data-token="${c.token}">Disable</button>`}
        </div>
      </div>`;
  }).join("");

  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AutoDial Admin</title>
  <style>
    body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px}
    h1{font-size:22px;margin:0 0 4px}
    .sub{color:#94a3b8;font-size:13px;margin-bottom:20px}
    .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
    .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px}
    .row{display:flex;justify-content:space-between;align-items:center;gap:10px;margin:4px 0}
    .machine{font-weight:600}
    .badge{font-size:12px;font-weight:700;padding:4px 10px;border-radius:999px}
    .online{background:#15803d;color:#fff}.offline{background:#b91c1c;color:#fff}.disabled{background:#475569;color:#e2e8f0}
    .meta{font-size:12px;color:#94a3b8;margin:10px 0;line-height:1.6}
    .btn{background:#2563eb;color:#fff;border:0;padding:8px 14px;border-radius:8px;cursor:pointer;font-weight:600}
    .btn.danger{background:#b91c1c}
    .btn:disabled{opacity:.5;cursor:default}
  </style></head><body>
  <h1>AutoDial Admin Portal</h1>
  <div class="sub">Free cloud control center — customer PC health &amp; remote disable</div>
  <div style="margin-bottom:16px"><button class="btn" id="logout" style="background:#475569">Sign out</button></div>
  <div class="grid">${cards || '<div class="card">No customers yet.</div>'}</div>
  <h2 style="margin-top:28px;font-size:17px;color:#e2e8f0">Recent AI calls</h2>
  <div class="grid">${callsHtml(calls)}</div>
  <h2 style="margin-top:28px;font-size:17px;color:#e2e8f0">Email outbox <span style="color:#94a3b8;font-weight:400">(if no SMTP configured)</span></h2>
  <pre style="background:#0b1220;border:1px solid #1e293b;padding:16px;border-radius:12px;color:#a5f3fc;font-size:12px;white-space:pre-wrap">${outbox.length ? outbox.map(o => `— ${esc(o.file)}\n${esc(o.content)}`).join("\n\n") : "No emails out yet."}</pre>
  <script>
    document.addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-action]');
      if (btn) {
        btn.disabled = true;
        const body = { token: btn.dataset.token, disabled: btn.dataset.action === 'disable' };
        await fetch('/api/disable', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
        location.reload();
        return;
      }
      if (e.target.id === 'logout') { await fetch('/logout', { method:'POST' }); location.href = '/'; }
    });
    function refresh(){ setTimeout(()=>location.reload(), 4000); }
    refresh();
  </script>
  </body></html>`;
}

function callsHtml(calls) {
  if (!calls.length) return '<div class="card" style="color:#94a3b8">No calls yet.</div>';
  return calls.map((c) => {
    const ok = c.good_lead === 1;
    return `<div class="card">
      <div class="row"><span class="machine">${esc(c.product || "call")}</span>
      <span class="${ok ? "badge online" : "badge offline"}">${ok ? "QUALIFIED" : c.escalated === 1 ? "ESCALATED" : "no lead"}</span></div>
      <div class="meta">Score: ${c.score}<br>${esc(String(c.summary || "").slice(0, 160))}</div>
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
    console.error("[portal] failed to start:", err);
    process.exit(1);
  });
}

module.exports = { start };
