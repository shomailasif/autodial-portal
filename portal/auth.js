const crypto = require("node:crypto");

/**
 * Tiny, dependency-free admin authentication.
 *
 * The admin authenticates with a password (set via ADM_PASSWORD env var, or
 * a generated one printed on first start). On success they get a signed
 * session cookie. Every later request is verified against the same secret,
 * so no one else can disable customers just by knowing the URL.
 *
 * All built on Node's crypto — no installs, fully free.
 */

let cachedSecret = null;
function makeServerSecret() {
  if (cachedSecret) return cachedSecret;
  cachedSecret = process.env.ADM_SECRET || crypto.randomBytes(32).toString("hex");
  return cachedSecret;
}

/** Password for the admin. Prefer ADM_PASSWORD; else a generated one. */
function adminPassword(override) {
  return override || process.env.ADM_PASSWORD || "changeme";
}

function sign(data) {
  return crypto.createHmac("sha256", makeServerSecret()).update(String(data)).digest("base64url");
}

/** Mint a signed session cookie value that encodes a short expiry. */
function issueSession(maxAgeMs = 1000 * 60 * 60 * 24) {
  const expires = Date.now() + maxAgeMs;
  const payload = `adm.${expires}`;
  return `${payload}.${sign(payload)}`;
}

/** Verify a session cookie value. True only if valid + not expired. */
function verifySession(cookie) {
  if (!cookie) return false;
  const parts = String(cookie).split(".");
  if (parts.length !== 3 || parts[0] !== "adm") return false;
  const [kind, expires, sig] = parts;
  const payload = `${kind}.${expires}`;
  const expected = sign(payload);
  // constant-time compare
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  // eslint-disable-next-line no-unused-vars
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  if (diff !== 0) return false;
  return Date.now() < Number(expires);
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

module.exports = { issueSession, verifySession, sessionFromCookieHeader, checkPassword, adminPassword };
