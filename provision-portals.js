#!/usr/bin/env node
/**
 * Magic Dialer — tenant portal PROVISIONING tool.
 *
 * Ships however many independent admin portals you need (1...1000+). Each
 * portal is hermetically isolated: its own PORTAL_ID, its own admin password,
 * its own branded name, and its own database — so no portal can ever see or
 * count the users of another (this is enforced at the database layer, see
 * db.js, and verified by test-portal-isolation.js).
 *
 * Usage:
 *   node provision-portals.js --count 3
 *   node provision-portals.js --count 100 --prefix office --name "Office Dispatch"
 *   node provision-portals.js --count 200 --db-url "postgres://..."   # shared Postgres, separate portal_id (no data overlap)
 *   node provision-portals.js --verify              # boot-check every bundle just generated
 *
 * Output:
 *   portals/<slug>/portal/        complete portal source (self-contained)
 *   portals/<slug>/.env           ready-to-run secrets (PORTAL_ID, ADM_PASSWORD, ...)
 *   portals/<slug>/.env.template  same keys, blank values for safe sharing
 *   portals/<slug>/start.ps1      one-click start for Windows
 *   portals/<slug>/start.sh       one-click start for Linux/cloud
 *   portals/<slug>/README.md      per-portal operator card
 *   portals/PORTALS.json          master manifest (never list the other portals' users)
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");

const ROOT = __dirname;                       // deploy/
const SRC_PORTAL = path.join(ROOT, "portal"); // the portal server source
const OUT = path.join(ROOT, "portals");
const MANIFEST = path.join(OUT, "PORTALS.json");

function arg(name, fallback) {
  const i = process.argv.indexOf("--" + name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}
const COUNT = Math.max(1, parseInt(arg("count", "1"), 10) || 1);
const PREFIX = arg("prefix", "portal");
const BASE_NAME = arg("name", "Magic Dialer Console");
const DB_URL = arg("db-url", "").trim();
const BOOT_CHECK = process.argv.includes("--verify");
const PORT_START = parseInt(arg("ports", "9000"), 10) || 9000;

function slug(i) {
  return `${PREFIX}-${String(i).padStart(3, "0")}`.replace(/[^a-zA-Z0-9._-]/g, "-");
}
function genPassword() {
  return crypto.randomBytes(9).toString("base64url").replace(/-/g, "x").slice(0, 14);
}

function ensurePortalSource() {
  if (!fs.existsSync(SRC_PORTAL)) {
    console.error(`Portal source not found at ${SRC_PORTAL}`);
    process.exit(2);
  }
}

function copyPortal(slugFolder) {
  const dest = path.join(slugFolder, "portal");
  fs.cpSync(SRC_PORTAL, dest, { recursive: true });
  // server.js requires ../shared/protocol - bring the shared module along so
  // every bundle is fully self-contained.
  fs.cpSync(path.join(ROOT, "shared"), path.join(slugFolder, "shared"), { recursive: true });
  return dest;
}

function writeEnv(slugFolder, cfg) {
  const entries = {
    PORTAL_ID: cfg.portalId,
    PORTAL_NAME: cfg.name,
    ADM_PASSWORD: cfg.password,
    AUTODIAL_PORT: String(cfg.port),
    ...(cfg.dbUrl ? { DATABASE_URL: cfg.dbUrl } : {}),
    SEARCH_ENGINE: "auto",
    SEARCH_API_KEY: "",
    LEAD_AUTO_HOURS: "6",
    SMTP_HOST: "",
    SMTP_PORT: "587",
    SMTP_USER: "",
    SMTP_PASS: "",
  };
  const lines = Object.entries(entries).map(([k, v]) => `${k}=${v}`);
  fs.writeFileSync(path.join(slugFolder, ".env"), lines.join("\n") + "\n", "utf8");
  fs.writeFileSync(
    path.join(slugFolder, ".env.template"),
    Object.keys(entries).map((k) => `${k}=`).join("\n") + "\n",
    "utf8",
  );
}

function writeLaunchers(slugFolder, port) {
  fs.writeFileSync(
    path.join(slugFolder, "start.ps1"),
    `# Starts this tenant portal. Run with:  powershell -ExecutionPolicy Bypass -File start.ps1
$envFile = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path -LiteralPath $envFile)) { Write-Host "Missing .env - copy from .env.template and fill it." -ForegroundColor Red; exit 1 }
Get-Content -LiteralPath $envFile | ForEach-Object {
  if ($_ -match "^([A-Za-z_][A-Za-z0-9_]*)=(.*)$") { Set-Item -Path ("env:" + $matches[1]) -Value $matches[2] }
}
$node = Join-Path $env:ProgramFiles "nodejs\\node.exe"
if (-not (Test-Path -LiteralPath $node)) { $node = "node" }
Write-Host "Starting Magic Dialer portal (\${env:PORTAL_ID}) on http://localhost:\${env:AUTODIAL_PORT}"
& $node (Join-Path $PSScriptRoot "portal\\server.js")
`,
    "utf8",
  );
  fs.writeFileSync(
    path.join(slugFolder, "start.sh"),
    `#!/bin/sh
# Starts this tenant portal. Run with:  bash start.sh
if [ ! -f .env ]; then echo "Missing .env - copy from .env.template and fill it."; exit 1; fi
export $(grep -v '^#' .env | xargs)
exec node portal/server.js
`,
    "utf8",
  );
}

function writeReadme(slugFolder, cfg) {
  const dbLine = cfg.dbUrl
    ? "- Shared durable Postgres (`DATABASE_URL` set). Portal gets its own `portal_id` =\n  `" + cfg.portalId + "` so no other portal can see its users."
    : "- Own SQLite file at `portal/portal.db` (zero-setup local/cloud). Swap to\n  Postgres for durable scaling by adding a `DATABASE_URL` to `.env`.";
  fs.writeFileSync(
    path.join(slugFolder, "README.md"),
    `# ${cfg.name}

Magic Dialer admin portal — tenant: **${cfg.portalId}**

This is one fully isolated admin portal. It cannot see, count, or act on the
users of any other portal, even on shared infrastructure.

- Admin URL: http://localhost:${cfg.port}
- Admin password: \`${cfg.password}\`
- Dashboard: log in, then use **Register** to create customer PCs. Each PC
  installs MagicDialer-Setup.exe and enters the portal URL + its access key.
- ${dbLine}

## Start (Windows)
    powershell -ExecutionPolicy Bypass -File start.ps1

## Start (Linux / cloud)
    bash start.sh

## Scale
- Thousands of customers on this portal? Add \`DATABASE_URL\` (free Neon
  Postgres) to \`.env\` — everything else stays identical.
- Want real operator search? Put a \`SEARCH_API_KEY\` (Serper/SerpAPI) in
  \`.env\` and set \`SEARCH_ENGINE\`.

## Ops notes
- Keep \`.env\` secret (it holds the admin password). \`.env.template\` is safe
  to share.
- New portal bundles: \`node provision-portals.js --count N\` (see PORTALS.json).
`,
    "utf8",
  );
}

function bootCheck(cfg, index) {
  return new Promise((resolve) => {
    const slugFolder = path.join(OUT, cfg.slug);
    const env = {};
    fs.readFileSync(path.join(slugFolder, ".env"), "utf8").split("\n").forEach((l) => {
      const m = l.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
      if (m) env[m[1]] = m[2];
    });
    env.PORT = String(cfg.port);
    const node = path.join(process.env.ProgramFiles || "C:\\Program Files", "nodejs", "node.exe");
    const child = spawn(node, [path.join(slugFolder, "portal", "server.js")], { env: { ...process.env, ...env }, stdio: ["ignore", "ignore", "pipe"] });
    let err = "";
    child.stderr.on("data", (d) => (err += d));
    const killer = () => { try { child.kill(); } catch {} };
    const timer = setTimeout(killer, 15000);
    const tryLogin = async () => {
      try {
        const r = await fetch(`http://127.0.0.1:${cfg.port}/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: cfg.password }),
        });
        const ck = r.headers.get("set-cookie");
        if (r.status === 200 && ck) {
          const rr = await fetch(`http://127.0.0.1:${cfg.port}/api/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json", Cookie: ck.split(";")[0] },
            body: JSON.stringify({ product: `${cfg.portalId} smoke`, leadFields: ["NAME"] }),
          });
          const ok = rr.status === 200;
          clearTimeout(timer);
          killer();
          if (!ok) { console.log(`  [${index}] ${cfg.slug}: login OK but register FAILED (${rr.status})`); resolve(false); return; }
          // Re-check scoped read: register a second customer and confirm count scoping via dashboard later; basics enough here.
          console.log(`  [${index}] ${cfg.slug}: boots, logins, registers - OK (port ${cfg.port})`);
          resolve(true);
          return;
        }
        clearTimeout(timer);
        killer();
        console.log(`  [${index}] ${cfg.slug}: login FAILED (${r.status})${err ? " - " + err.slice(0, 120) : ""}`);
        resolve(false);
      } catch (e) {
        clearTimeout(timer);
        killer();
        console.log(`  [${index}] ${cfg.slug}: not reachable yet (${e.message})`);
        resolve(false);
      }
    };
    // Wait for listen then probe.
    let tries = 0;
    const probe = setInterval(async () => {
      tries++;
      try {
        await fetch(`http://127.0.0.1:${cfg.port}/login`, { method: "GET" });
        clearInterval(probe);
        tryLogin();
      } catch {
        if (tries > 30) { clearInterval(probe); clearTimeout(timer); killer(); console.log(`  [${index}] ${cfg.slug}: never came up`); resolve(null); }
      }
    }, 250);
  });
}

async function main() {
  if (!fs.existsSync(OUT)) fs.mkdirSync(OUT, { recursive: true });
  ensurePortalSource();

  const manifest = fs.existsSync(MANIFEST) ? JSON.parse(fs.readFileSync(MANIFEST, "utf8")) : { generatedAt: null, portals: [] };

  console.log(`Provisioning ${COUNT} isolated admin portals ...`);
  const created = [];
  for (let i = 1; i <= COUNT; i++) {
    const s = slug(i);
    const portalId = s;
    const cfg = {
      slug: s,
      portalId,
      name: COUNT > 1 ? `${BASE_NAME} #${i}` : BASE_NAME,
      password: genPassword(),
      port: PORT_START + i - 1,
      dbUrl: DB_URL,
    };
    const slugFolder = path.join(OUT, s);
    if (fs.existsSync(slugFolder)) fs.rmSync(slugFolder, { recursive: true, force: true });
    fs.mkdirSync(slugFolder, { recursive: true });
    copyPortal(slugFolder);
    writeEnv(slugFolder, cfg);
    writeLaunchers(slugFolder, cfg.port);
    writeReadme(slugFolder, cfg);
    manifest.portals = manifest.portals.filter((p) => p.slug !== s);
    manifest.portals.push({ slug: s, portalId, name: cfg.name, port: cfg.port, password: cfg.password, dbMode: cfg.dbUrl ? "postgres" : "sqlite", createdAt: new Date().toISOString() });
    created.push(cfg);
    console.log(`  created ${s} -> portals/${s} (password ${cfg.password}, port ${cfg.port})`);
  }
  manifest.generatedAt = new Date().toISOString();
  manifest.total = manifest.portals.length;
  fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2), "utf8");
  console.log(`\nManifest: ${MANIFEST} (${manifest.total} portals total)`);

  if (BOOT_CHECK) {
    console.log("\nBoot-checking every bundle (login + register)...");
    const todo = created.slice().reverse(); // newest first (cheap ports freed); still sequential to keep wait times low
    for (let i = 0; i < todo.length; i++) {
      await bootCheck(todo[i], i + 1);
      await new Promise((r) => setTimeout(r, 300));
    }
  } else {
    console.log("\nTip: re-run with --verify to boot-check every bundle.");
  }
}

main().catch((e) => { console.error(e); process.exit(1); });