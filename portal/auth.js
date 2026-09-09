const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

/**
 * Tiny, dependency-free admin authentication.
 *
 * Admins authenticate with their own password. On success they get a signed
 * session cookie that also records WHICH admin logged in. Every later request
 * is verified against the same secret, so no one else can disable customers
 * just by knowing the URL — and different admins never see each other.
 *
 * Admin identities live in admins.json next to this file (salted PBKDF2
 * hashes). When that file exists, ONLY those admins can log in (no shared
 * back door). When it is absent (tests, fresh dev), the legacy single
 * ADM_PASSWORD path applies.
 *
 * All built on Node's crypto — no installs, fully free.
 */

let cachedSecret = null;
function makeServerSecret() {
  if (cachedSecret) return cachedSecret;
  cachedSecret = process.env.ADM_SECRET || crypto.randomBytes(32).toString("hex");
  return cachedSecret;
}

/** Password for the legacy single-admin fallback. */
function adminPassword(override) {
  return override || process.env.ADM_PASSWORD || "changeme";
}

const ADMINS_FILE = path.join(__dirname, "admins.json");
let adminsCache = null;
function admins() {
  if (adminsCache) return adminsCache;
  try {
    if (fs.existsSync(ADMINS_FILE)) {
      const list = JSON.parse(fs.readFileSync(ADMINS_FILE, "utf8"));
      if (Array.isArray(list) && list.length > 0) adminsCache = list;
    }
  } catch {}
  return adminsCache || null;
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(String(password), String(salt), 100000, 32, "sha256").toString("hex");
}

/**
 * Resolve a password to an admin identity, or null. When admins.json exists
 * it is the ONLY source of truth. Otherwise the legacy password is mapped to
 * the "owner" admin.
 */
function authenticate(password, override) {
  const list = admins();
  if (list && list.length) {
    const attempt = Buffer.from(String(password || ""));
    for (const a of list) {
      const expected = Buffer.from(hashPassword(password, a.salt), "hex");
      if (expected.length === attempt.length) {
        let diff = 0;
        for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ attempt[i];
        if (diff === 0) return { id: a.id || a.email, email: a.email, name: a.name || "Admin" };
      } else {
        // Timing-safe path for mismatched lengths.
        let diff = 0;
        for (let i = 0; i < attempt.length; i++) diff |= attempt[i] ^ expected[i % expected.length];
        if (diff === 0 && attempt.length === 0 && expected.length === 0) return null;
      }
    }
    return null;
  }
  return checkPassword(password, override) ? { id: "owner", email: null, name: "Owner" } : null;
}

function sign(data) {
  return crypto.createHmac("sha256", makeServerSecret()).update(String(data)).digest("base64url");
}

/** Mint a signed session cookie value that encodes expiry + admin id. */
function issueSession(identityId, maxAgeMs = 1000 * 60 * 60 * 24) {
  const expires = Date.now() + maxAgeMs;
  const encId = Buffer.from(String(identityId || "owner")).toString("base64url");
  const payload = `adm.${expires}.${encId}`;
  return `${payload}.${sign(payload)}`;
}

/**
 * Mint a CUSTOMER session (self-service login by access token). The token is
 * HMAC-signed into the cookie, so a forged cookie is rejected and the server
 * needs no session store.
 */
function issueCustomerSession(token, maxAgeMs = 1000 * 60 * 60 * 24) {
  const expires = Date.now() + maxAgeMs;
  const enc = Buffer.from(String(token)).toString("base64url");
  const payload = `cus.${enc}.${expires}`;
  return `${payload}.${sign(payload)}`;
}

/**
 * Verify a customer session cookie. Returns the customer's access token, or
 * null when the cookie is missing / forged / expired.
 */
function verifyCustomerSession(cookie) {
  if (!cookie) return null;
  const parts = String(cookie).split(".");
  if (parts.length !== 4 || parts[0] !== "cus") return null;
  const enc = parts[1];
  const expires = parts[2];
  const payload = `cus.${enc}.${expires}`;
  const expected = sign(payload);
  const a = Buffer.from(parts[3]);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return null;
  // eslint-disable-next-line no-unused-vars
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  if (diff !== 0) return null;
  if (Date.now() >= Number(expires)) return null;
  try { return Buffer.from(enc, "base64url").toString("utf8"); } catch { return null; }
}

/** Pull the customer session value out of a Cookie request header. */
function customerSessionFromCookieHeader(header) {
  if (!header) return null;
  for (const part of String(header).split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === "csession") return rest.join("=");
  }
  return null;
}

/** Verify a session cookie value. True only if valid + not expired. */
function verifySession(cookie) {
  if (!cookie) return false;
  const parts = String(cookie).split(".");
  if (parts.length !== 3 && parts.length !== 4) return false;
  if (parts[0] !== "adm") return false;
  const payload = `${parts[0]}.${parts[1]}.${parts[2]}`;
  const expected = sign(payload);
  // constant-time compare
  const a = Buffer.from(parts[3]);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  // eslint-disable-next-line no-unused-vars
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  if (diff !== 0) return false;
  return Date.now() < Number(parts[1]);
}

/** Which admin identity owns a valid session cookie, or null. */
function sessionIdentity(cookie) {
  const parts = cookie ? String(cookie).split(".") : [];
  if (parts.length !== 4 || !verifySession(cookie)) return null;
  try { return Buffer.from(parts[2], "base64url").toString("utf8") || "owner"; } catch { return null; }
}

/** Pull the session value out of a Cookie request header. */
function sessionFromCookieHeader(header) {
  if (!header) return null;
  for (const part of String(header).split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === "session") return rest.join("=");
  }
  return null;
}

/** Timing-safe password check. */
function checkPassword(attempt, override) {
  const a = Buffer.from(String(attempt || ""));
  const b = Buffer.from(adminPassword(override));
  if (a.length !== b.length) return false;
  // eslint-disable-next-line no-unused-vars
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

module.exports = { issueSession, verifySession, sessionIdentity, sessionFromCookieHeader, checkPassword, adminPassword, authenticate, issueCustomerSession, verifyCustomerSession, customerSessionFromCookieHeader };
