const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");

/**
 * Portal database â€” DUAL BACKEND.
 *
 *  - When `DATABASE_URL` is set (e.g. a free Neon Postgres URL), the portal
 *    uses Postgres (the `pg` client). This is what you want on free PaaS
 *    hosts (Koyeb/Render) because their local disk is ephemeral and resets
 *    on restart â€” a cloud DB keeps customers, calls and disable state safe.
 *  - Otherwise it falls back to the local SQLite file (node:sqlite) so the
 *    portal still works fully offline / in local dev with zero setup.
 *
 * Every exported function is ASYNC (returns a Promise) in both backends so
 * callers can `await` uniformly.
 *
 * The `db` object handed to callers is an opaque handle:
 *  - Postgres backends: a `pg.Pool` wrapped as { pool }.
 *  - SQLite backends: the DatabaseSync object wrapped as { sqlite }.
 */

const USES_PG = !!process.env.DATABASE_URL;

/**
 * Tenant identity for this portal instance.
 *
 * Each deployed portal runs with its own PORTAL_ID (default "main"). Every
 * customer and call is stamped with the portal it was created on, and every
 * read is scoped to the current portal - so even if two portals share the same
 * database, neither can see or count the other's users.
 */
function portalId() {
  return String(process.env.PORTAL_ID || "main");
}

let pgPool = null;
async function getPool() {
  if (!USES_PG) return null;
  if (pgPool) return pgPool;
  const { Pool } = require("pg");
  pgPool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await pgPool.query("SELECT 1");
  return pgPool;
}

async function openDb(dbPath) {
  const sid = portalId();
  if (USES_PG) {
    const pool = await getPool();
    await initPostgres(pool);
    return { pool, portalId: sid };
  }
  if (dbPath !== ":memory:") {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  }
  const { DatabaseSync } = require("node:sqlite");
  const db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS customers (
      token        TEXT PRIMARY KEY,
      machine_id   TEXT,
      product      TEXT,
      lead_fields  TEXT,
      contact_email TEXT,
      persona      TEXT,
      settings     TEXT,
      call_list    TEXT,
      leads_found  TEXT,
      leads_searched_at INTEGER,
      created_at   INTEGER NOT NULL,
      last_seen    INTEGER,
      status       TEXT NOT NULL DEFAULT 'online',
      disabled     INTEGER NOT NULL DEFAULT 0,
      voip_ready   INTEGER NOT NULL DEFAULT 0,
      portal_id    TEXT NOT NULL DEFAULT 'main'
    );
    CREATE TABLE IF NOT EXISTS calls (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_token TEXT,
      product      TEXT,
      transcript   TEXT,
      score        REAL,
      good_lead    INTEGER NOT NULL DEFAULT 0,
      escalated    INTEGER NOT NULL DEFAULT 0,
      strategies   TEXT,
      summary      TEXT,
      created_at   INTEGER NOT NULL,
      portal_id    TEXT NOT NULL DEFAULT 'main'
    );
  `);
  const cols = db.prepare("PRAGMA table_info(customers)").all();
  for (const col of [["voip_ready", "INTEGER NOT NULL DEFAULT 0"], ["settings", "TEXT"], ["call_list", "TEXT"], ["leads_found", "TEXT"], ["leads_searched_at", "INTEGER"], ["portal_id", "TEXT NOT NULL DEFAULT 'main'"]]) {
    if (!cols.some((c) => c.name === col[0])) {
      db.exec(`ALTER TABLE customers ADD COLUMN ${col[0]} ${col[1]}`);
    }
  }
  const callCols = db.prepare("PRAGMA table_info(calls)").all();
  if (!callCols.some((c) => c.name === "strategies")) {
    db.exec("ALTER TABLE calls ADD COLUMN strategies TEXT");
  }
  if (!callCols.some((c) => c.name === "portal_id")) {
    db.exec("ALTER TABLE calls ADD COLUMN portal_id TEXT NOT NULL DEFAULT 'main'");
  }
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_customers_portal ON customers(portal_id);
    CREATE INDEX IF NOT EXISTS idx_calls_portal ON calls(portal_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_calls_customer ON calls(customer_token);
    CREATE INDEX IF NOT EXISTS idx_customers_machine ON customers(machine_id, portal_id);
  `);
  return { sqlite: db, portalId: sid };
}

async function initPostgres(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      token        TEXT PRIMARY KEY,
      machine_id   TEXT,
      product      TEXT,
      lead_fields  TEXT,
      contact_email TEXT,
      persona      TEXT,
      settings     TEXT,
      call_list    TEXT,
      leads_found  TEXT,
      leads_searched_at BIGINT,
      created_at   BIGINT NOT NULL,
      last_seen    BIGINT,
      status       TEXT NOT NULL DEFAULT 'online',
      disabled     INTEGER NOT NULL DEFAULT 0,
      voip_ready   INTEGER NOT NULL DEFAULT 0,
      portal_id    TEXT NOT NULL DEFAULT 'main'
    );
    CREATE TABLE IF NOT EXISTS calls (
      id           BIGSERIAL PRIMARY KEY,
      customer_token TEXT,
      product      TEXT,
      transcript   TEXT,
      score        DOUBLE PRECISION,
      good_lead    INTEGER NOT NULL DEFAULT 0,
      escalated    INTEGER NOT NULL DEFAULT 0,
      strategies   TEXT,
      summary      TEXT,
      created_at   BIGINT NOT NULL,
      portal_id    TEXT NOT NULL DEFAULT 'main'
    );
  `);
  // Migrations for deployments that already exist (CREATE IF NOT EXISTS never
  // adds columns): the platform features + strategies need these columns, or
  // saveLeads/updateCustomer/call-result crashes on a pre-existing DB.
  for (const ddl of [
    "ALTER TABLE customers ADD COLUMN IF NOT EXISTS voip_ready INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE customers ADD COLUMN IF NOT EXISTS settings TEXT",
    "ALTER TABLE customers ADD COLUMN IF NOT EXISTS call_list TEXT",
    "ALTER TABLE customers ADD COLUMN IF NOT EXISTS leads_found TEXT",
    "ALTER TABLE customers ADD COLUMN IF NOT EXISTS leads_searched_at BIGINT",
    "ALTER TABLE customers ADD COLUMN IF NOT EXISTS portal_id TEXT NOT NULL DEFAULT 'main'",
    "ALTER TABLE calls ADD COLUMN IF NOT EXISTS strategies TEXT",
    "ALTER TABLE calls ADD COLUMN IF NOT EXISTS portal_id TEXT NOT NULL DEFAULT 'main'",
  ]) {
    await pool.query(ddl).catch(() => {}); // ignore benign duplicates / lock races
  }
  for (const idx of [
    "CREATE INDEX IF NOT EXISTS idx_customers_portal ON customers(portal_id)",
    "CREATE INDEX IF NOT EXISTS idx_calls_portal ON calls(portal_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_calls_customer ON calls(customer_token)",
    "CREATE INDEX IF NOT EXISTS idx_customers_machine ON customers(machine_id, portal_id)",
  ]) {
    await pool.query(idx).catch(() => {});
  }
}

function rowToCustomer(r) {
  if (!r) return null;
  return {
    token: r.token,
    machine_id: r.machine_id,
    product: r.product,
    lead_fields: r.lead_fields,
    contact_email: r.contact_email,
    persona: r.persona,
    settings: safeParseObj(r.settings),
    call_list: safeParseArr(r.call_list),
    leads_found: safeParseArr(r.leads_found),
    leads_searched_at: r.leads_searched_at == null ? null : Number(r.leads_searched_at),
    created_at: Number(r.created_at),
    last_seen: r.last_seen == null ? null : Number(r.last_seen),
    status: r.status,
    disabled: Number(r.disabled),
    voip_ready: Number(r.voip_ready),
    portal_id: r.portal_id,
  };
}

async function registerCustomer(db, { product, leadFields, contactEmail, persona }) {
  const token = crypto.randomBytes(24).toString("hex");
  const machineId = crypto.randomUUID();
  const created = Date.now();
  const leadJson = JSON.stringify(leadFields || []);
  if (db.pool) {
    await db.pool.query(
      `INSERT INTO customers (token, machine_id, product, lead_fields, contact_email, persona, created_at, portal_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [token, machineId, product || null, leadJson, contactEmail || null, persona || "High-energy friendly helper", created, db.portalId],
    );
    return { token, machineId, product, leadFields, contactEmail, persona: persona || "High-energy friendly helper" };
  }
  db.sqlite.prepare(
    `INSERT INTO customers (token, machine_id, product, lead_fields, contact_email, persona, created_at, portal_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(token, machineId, product || null, leadJson, contactEmail || null, persona || "High-energy friendly helper", created, db.portalId);
  const row = db.sqlite.prepare("SELECT * FROM customers WHERE token = ?").get(token);
  const c = rowToCustomer(row);
  return { token, machineId: c.machine_id, product: c.product, leadFields, contactEmail: c.contact_email, persona: c.persona };
}

async function findCustomerByMachine(db, machineId) {
  if (!machineId) return null;
  if (db.pool) {
    const r = await db.pool.query("SELECT * FROM customers WHERE machine_id = $1 AND portal_id = $2", [machineId, db.portalId]);
    return rowToCustomer(r.rows[0]);
  }
  return rowToCustomer(db.sqlite.prepare("SELECT * FROM customers WHERE machine_id = ? AND portal_id = ?").get(machineId, db.portalId));
}

async function getCustomerByToken(db, token) {
  if (typeof token !== "string" || !token) return null;
  if (db.pool) {
    const r = await db.pool.query("SELECT * FROM customers WHERE token = $1 AND portal_id = $2", [token, db.portalId]);
    return rowToCustomer(r.rows[0]);
  }
  return rowToCustomer(db.sqlite.prepare("SELECT * FROM customers WHERE token = ? AND portal_id = ?").get(token, db.portalId));
}

async function processHeartbeat(db, { token, voipReady }) {
  if (typeof token !== "string" || !token) {
    return { ok: false, disabled: true, reason: "unknown" };
  }
  const c = await getCustomerByToken(db, token);
  if (!c) return { ok: false, disabled: true, reason: "unknown" };
  const now = Date.now();
  const vp = voipReady ? 1 : 0;
  if (db.pool) {
    await db.pool.query(
      "UPDATE customers SET last_seen = $1, status = 'online', voip_ready = $2 WHERE token = $3",
      [now, vp, token],
    );
  } else {
    db.sqlite.prepare("UPDATE customers SET last_seen = ?, status = 'online', voip_ready = ? WHERE token = ?").run(now, vp, token);
  }
  return {
    ok: true,
    disabled: c.disabled === 1,
    since: new Date(c.disabled === 1 ? c.last_seen || 0 : 0).toISOString(),
    config: {
      token,
      product: c.product,
      leadFields: safeParse(c.lead_fields),
      contactEmail: c.contact_email,
      persona: c.persona,
      voipReady: (vp ? 1 : c.voip_ready) === 1,
      companyName: (c.settings && c.settings.companyName) || null,
      callbackNumber: (c.settings && c.settings.callbackNumber) || null,
      callbackIn: (c.settings && c.settings.callbackIn) || null,
      callList: c.call_list || [],
      searchEnabled: !(c.settings && c.settings.searchEnabled === false),
      lang: (c.settings && /^(en|es|fr|de|pt|hi|auto)$/.test(c.settings.lang)) ? c.settings.lang : "en",
      voiceStyle: (c.settings && /^(human|frank|friendly)$/.test(c.settings.voiceStyle)) ? c.settings.voiceStyle : "human",
    },
  };
}

/**
 * Apply an admin edit to a customer (sales form fields + agent settings).
 * Only provided keys are updated; null settings keys are cleared to "".
 */
async function updateCustomer(db, token, patch) {
  const c = await getCustomerByToken(db, token);
  if (!c) return null;
  const upd = [];
  const vals = [];
  const push = (col, v) => { upd.push(col); vals.push(v); };
  if (typeof patch.product === "string") push("product", patch.product || null);
  if (Array.isArray(patch.leadFields)) push("lead_fields", JSON.stringify(patch.leadFields));
  if (typeof patch.contactEmail === "string") push("contact_email", patch.contactEmail || null);
  if (typeof patch.persona === "string") push("persona", patch.persona || null);
  if (patch.settings && typeof patch.settings === "object") {
    const merged = { ...(c.settings || {}) };
    for (const k of ["companyName", "callbackNumber", "callbackIn", "searchEnabled", "lang", "voiceStyle"]) {
      if (k in patch.settings) {
        // Reject invalid language codes so a typo never clobbers a good value.
        if (k === "lang" && !/^(en|es|fr|de|pt|hi|auto)$/.test(String(patch.settings.lang))) continue;
        if (k === "voiceStyle" && !/^(human|frank|friendly)$/.test(String(patch.settings.voiceStyle))) continue;
        merged[k] = patch.settings[k];
      }
    }
    push("settings", JSON.stringify(merged));
  }

  if (upd.length) {
    if (db.pool) {
      const setSql = upd.map((col, i) => `${col} = $${i + 1}`).join(", ");
      await db.pool.query(`UPDATE customers SET ${setSql} WHERE token = $${upd.length + 1}`, [...vals, token]);
    } else {
      const setSql = upd.map((col) => `${col} = ?`).join(", ");
      db.sqlite.prepare(`UPDATE customers SET ${setSql} WHERE token = ?`).run(...vals, token);
    }
  }
  return getCustomerByToken(db, token);
}

async function setCallList(db, token, list) {
  const c = await getCustomerByToken(db, token);
  if (!c) return null;
  const arr = Array.isArray(list) ? list.map((n) => String(n).trim()).filter(Boolean) : [];
  const json = JSON.stringify(arr);
  if (db.pool) {
    await db.pool.query("UPDATE customers SET call_list = $1 WHERE token = $2", [json, token]);
  } else {
    db.sqlite.prepare("UPDATE customers SET call_list = ? WHERE token = ?").run(json, token);
  }
  return setCallListRaw(db, token, arr);
}

/** Save the internet-found leads for a customer and stamp when we searched.
 * Each lead gets a stable id (derived from its source) and duplicates are
 * dropped, so remove/reseat commands always work. */
async function saveLeads(db, token, leads) {
  const c = await getCustomerByToken(db, token);
  const seen = new Set();
  const arr = [];
  for (const raw of Array.isArray(leads) ? leads : []) {
    const lead = raw && typeof raw === "object" ? raw : { title: String(raw) };
    const key = String(lead.source || lead.title || "");
    if (!key) continue;
    lead.id = lead.id || crypto.createHash("md5").update(key).digest("hex").slice(0, 16);
    if (seen.has(lead.id)) continue;
    seen.add(lead.id);
    arr.push(lead);
  }
  const json = JSON.stringify(arr.slice(0, 200));
  const now = Date.now();
  if (db.pool) {
    await db.pool.query("UPDATE customers SET leads_found = $1, leads_searched_at = $2 WHERE token = $3", [json, now, token]);
  } else {
    db.sqlite.prepare("UPDATE customers SET leads_found = ?, leads_searched_at = ? WHERE token = ?").run(json, now, token);
  }
  if (!c) return null;
  return getCustomerByToken(db, token);
}

async function setCallListRaw(db, token, arr) {
  const c = await getCustomerByToken(db, token);
  if (!c) return null;
  const json = JSON.stringify(arr);
  if (db.pool) {
    await db.pool.query("UPDATE customers SET call_list = $1 WHERE token = $2", [json, token]);
    const r = await db.pool.query("SELECT * FROM customers WHERE token = $1", [token]);
    return rowToCustomer(r.rows[0]);
  }
  db.sqlite.prepare("UPDATE customers SET call_list = ? WHERE token = ?").run(json, token);
  return rowToCustomer(db.sqlite.prepare("SELECT * FROM customers WHERE token = ?").get(token));
}

async function setDisabled(db, token, disabled) {
  const c = await getCustomerByToken(db, token);
  if (!c) return null;
  const v = disabled ? 1 : 0;
  if (db.pool) {
    await db.pool.query("UPDATE customers SET disabled = $1, status = 'online' WHERE token = $2", [v, token]);
    const r = await db.pool.query("SELECT * FROM customers WHERE token = $1", [token]);
    return rowToCustomer(r.rows[0]);
  }
  db.sqlite.prepare("UPDATE customers SET disabled = ?, status = 'online' WHERE token = ?").run(v, token);
  return rowToCustomer(db.sqlite.prepare("SELECT * FROM customers WHERE token = ?").get(token));
}

async function markStaleOffline(db, maxAgeMs) {
  const cutoff = Date.now() - maxAgeMs;
  if (db.pool) {
    await db.pool.query("UPDATE customers SET status = 'offline' WHERE last_seen < $1 AND status != 'offline' AND portal_id = $2", [cutoff, db.portalId]);
  } else {
    db.sqlite.prepare("UPDATE customers SET status = 'offline' WHERE last_seen < ? AND status != 'offline' AND portal_id = ?").run(cutoff, db.portalId);
  }
}

async function allCustomers(db) {
  if (db.pool) {
    const r = await db.pool.query("SELECT * FROM customers WHERE portal_id = $1 ORDER BY created_at ASC", [db.portalId]);
    return r.rows.map(rowToCustomer);
  }
  return db.sqlite.prepare("SELECT * FROM customers WHERE portal_id = ? ORDER BY created_at ASC").all(db.portalId).map(rowToCustomer);
}

async function logCall(db, call) {
  const created = Date.now();
  const transcript = typeof call.transcript === "string" ? call.transcript : JSON.stringify(call.transcript || []);
  const strategies = call.strategies ? JSON.stringify(call.strategies) : null;
  // Attribute the call to the portal that owns the customer, never to anyone
  // else's portal (getCustomerByToken is portal-scoped, so a foreign token
  // resolves to null here and the call is recorded to this instance instead).
  const owner = call.customerToken ? await getCustomerByToken(db, call.customerToken) : null;
  const ply = owner ? owner.portal_id : db.portalId;
  if (db.pool) {
    await db.pool.query(
      `INSERT INTO calls (customer_token, product, transcript, score, good_lead, escalated, strategies, summary, created_at, portal_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [call.customerToken || null, call.product || null, transcript, call.score ?? null, call.goodLead ? 1 : 0, call.escalateToHuman ? 1 : 0, strategies, call.summary || null, created, ply],
    );
    return;
  }
  db.sqlite.prepare(
    `INSERT INTO calls (customer_token, product, transcript, score, good_lead, escalated, strategies, summary, created_at, portal_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(call.customerToken || null, call.product || null, transcript, call.score ?? null, call.goodLead ? 1 : 0, call.escalateToHuman ? 1 : 0, strategies, call.summary || null, created, ply);
}

async function allCalls(db, limit = 20) {
  if (db.pool) {
    const r = await db.pool.query("SELECT * FROM calls WHERE portal_id = $1 ORDER BY created_at DESC LIMIT $2", [db.portalId, limit || 20]);
    return r.rows;
  }
  return db.sqlite.prepare("SELECT * FROM calls WHERE portal_id = ? ORDER BY created_at DESC LIMIT ?").all(db.portalId, limit || 20);
}

async function getCallById(db, id) {
  const n = Number(id);
  if (!Number.isFinite(n)) return null;
  if (db.pool) {
    const r = await db.pool.query("SELECT * FROM calls WHERE id = $1 AND portal_id = $2", [n, db.portalId]);
    return r.rows[0] || null;
  }
  return db.sqlite.prepare("SELECT * FROM calls WHERE id = ? AND portal_id = ?").get(n, db.portalId) || null;
}

function safeParse(s) {
  if (!s) return [];
  try {
    const v = JSON.parse(s);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

function safeParseArr(s) {
  if (s == null || s === "") return [];
  try {
    const v = JSON.parse(s);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

function safeParseObj(s) {
  if (s == null || s === "") return {};
  try {
    const v = JSON.parse(s);
    return v && typeof v === "object" && !Array.isArray(v) ? v : {};
  } catch {
    return {};
  }
}

module.exports = {
  openDb,
  portalId,
  registerCustomer,
  findCustomerByMachine,
  getCustomerByToken,
  processHeartbeat,
  setDisabled,
  markStaleOffline,
  allCustomers,
  logCall,
  allCalls,
  getCallById,
  updateCustomer,
  setCallList,
  saveLeads,
  USES_PG,
};
