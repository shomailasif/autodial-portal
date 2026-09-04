const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");

/**
 * Portal database — DUAL BACKEND.
 *
 *  - When `DATABASE_URL` is set (e.g. a free Neon Postgres URL), the portal
 *    uses Postgres (the `pg` client). This is what you want on free PaaS
 *    hosts (Koyeb/Render) because their local disk is ephemeral and resets
 *    on restart — a cloud DB keeps customers, calls and disable state safe.
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
  if (USES_PG) {
    const pool = await getPool();
    await initPostgres(pool);
    return { pool };
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
      created_at   INTEGER NOT NULL,
      last_seen    INTEGER,
      status       TEXT NOT NULL DEFAULT 'online',
      disabled     INTEGER NOT NULL DEFAULT 0,
      voip_ready   INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS calls (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_token TEXT,
      product      TEXT,
      transcript   TEXT,
      score        REAL,
      good_lead    INTEGER NOT NULL DEFAULT 0,
      escalated    INTEGER NOT NULL DEFAULT 0,
      summary      TEXT,
      created_at   INTEGER NOT NULL
    );
  `);
  const cols = db.prepare("PRAGMA table_info(customers)").all();
  if (!cols.some((c) => c.name === "voip_ready")) {
    db.exec("ALTER TABLE customers ADD COLUMN voip_ready INTEGER NOT NULL DEFAULT 0");
  }
  return { sqlite: db };
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
      created_at   BIGINT NOT NULL,
      last_seen    BIGINT,
      status       TEXT NOT NULL DEFAULT 'online',
      disabled     INTEGER NOT NULL DEFAULT 0,
      voip_ready   INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS calls (
      id           BIGSERIAL PRIMARY KEY,
      customer_token TEXT,
      product      TEXT,
      transcript   TEXT,
      score        DOUBLE PRECISION,
      good_lead    INTEGER NOT NULL DEFAULT 0,
      escalated    INTEGER NOT NULL DEFAULT 0,
      summary      TEXT,
      created_at   BIGINT NOT NULL
    );
  `);
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
    created_at: Number(r.created_at),
    last_seen: r.last_seen == null ? null : Number(r.last_seen),
    status: r.status,
    disabled: Number(r.disabled),
    voip_ready: Number(r.voip_ready),
  };
}

async function registerCustomer(db, { product, leadFields, contactEmail, persona }) {
  const token = crypto.randomBytes(24).toString("hex");
  const machineId = crypto.randomUUID();
  const created = Date.now();
  const leadJson = JSON.stringify(leadFields || []);
  if (db.pool) {
    await db.pool.query(
      `INSERT INTO customers (token, machine_id, product, lead_fields, contact_email, persona, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [token, machineId, product || null, leadJson, contactEmail || null, persona || "High-energy friendly helper", created],
    );
    return { token, machineId, product, leadFields, contactEmail, persona: persona || "High-energy friendly helper" };
  }
  db.sqlite.prepare(
    `INSERT INTO customers (token, machine_id, product, lead_fields, contact_email, persona, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(token, machineId, product || null, leadJson, contactEmail || null, persona || "High-energy friendly helper", created);
  const row = db.sqlite.prepare("SELECT * FROM customers WHERE token = ?").get(token);
  const c = rowToCustomer(row);
  return { token, machineId: c.machine_id, product: c.product, leadFields, contactEmail: c.contact_email, persona: c.persona };
}

async function findCustomerByMachine(db, machineId) {
  if (!machineId) return null;
  if (db.pool) {
    const r = await db.pool.query("SELECT * FROM customers WHERE machine_id = $1", [machineId]);
    return rowToCustomer(r.rows[0]);
  }
  return rowToCustomer(db.sqlite.prepare("SELECT * FROM customers WHERE machine_id = ?").get(machineId));
}

async function getCustomerByToken(db, token) {
  if (typeof token !== "string" || !token) return null;
  if (db.pool) {
    const r = await db.pool.query("SELECT * FROM customers WHERE token = $1", [token]);
    return rowToCustomer(r.rows[0]);
  }
  return rowToCustomer(db.sqlite.prepare("SELECT * FROM customers WHERE token = ?").get(token));
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
      product: c.product,
      leadFields: safeParse(c.lead_fields),
      contactEmail: c.contact_email,
      persona: c.persona,
      voipReady: (vp ? 1 : c.voip_ready) === 1,
    },
  };
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
    await db.pool.query("UPDATE customers SET status = 'offline' WHERE last_seen < $1 AND status != 'offline'", [cutoff]);
  } else {
    db.sqlite.prepare("UPDATE customers SET status = 'offline' WHERE last_seen < ? AND status != 'offline'").run(cutoff);
  }
}

async function allCustomers(db) {
  if (db.pool) {
    const r = await db.pool.query("SELECT * FROM customers ORDER BY created_at ASC");
    return r.rows.map(rowToCustomer);
  }
  return db.sqlite.prepare("SELECT * FROM customers ORDER BY created_at ASC").all().map(rowToCustomer);
}

async function logCall(db, call) {
  const created = Date.now();
  const transcript = typeof call.transcript === "string" ? call.transcript : JSON.stringify(call.transcript || []);
  if (db.pool) {
    await db.pool.query(
      `INSERT INTO calls (customer_token, product, transcript, score, good_lead, escalated, summary, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [call.customerToken || null, call.product || null, transcript, call.score ?? null, call.goodLead ? 1 : 0, call.escalateToHuman ? 1 : 0, call.summary || null, created],
    );
    return;
  }
  db.sqlite.prepare(
    `INSERT INTO calls (customer_token, product, transcript, score, good_lead, escalated, summary, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(call.customerToken || null, call.product || null, transcript, call.score ?? null, call.goodLead ? 1 : 0, call.escalateToHuman ? 1 : 0, call.summary || null, created);
}

async function allCalls(db, limit = 20) {
  if (db.pool) {
    const r = await db.pool.query("SELECT * FROM calls ORDER BY created_at DESC LIMIT $1", [limit || 20]);
    return r.rows;
  }
  return db.sqlite.prepare("SELECT * FROM calls ORDER BY created_at DESC LIMIT ?").all(limit || 20);
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

module.exports = {
  openDb,
  registerCustomer,
  findCustomerByMachine,
  getCustomerByToken,
  processHeartbeat,
  setDisabled,
  markStaleOffline,
  allCustomers,
  logCall,
  allCalls,
  USES_PG,
};
