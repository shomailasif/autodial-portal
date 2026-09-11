/*
 * Cloud call gateway - trunk layer.
 *
 * All outbound dialing happens HERE, in the cloud, over ordinary HTTPS(443).
 * Customer PCs never open SIP ports; their agent only talks to a portal over
 * 443 (heartbeat / future WSS media channel). This is what lets the product
 * work on any ISP / hotel Wi-Fi / office firewall.
 *
 * Trunk drivers are selected by the customer's voip.provider string:
 *   - "ringcentral" : RingOut (REST) from the portal over 443
 *   - "sim"         : simulated lifecycle for dry-runs + automated tests
 *   - anything else : currently routed to a stub until the cloud SIP
 *                     registration bridge lands.
 */
const crypto = require("node:crypto");
const tls = require("node:tls");
const net = require("node:net");
const { sipCallOnce } = require("./softphone");
const audio = require("./audio");
const learning = require("./learning");
const { updateCustomer } = require("./db");

// Hosted provider -> default SIP registration domain (used by the cloud to
// register the trunk later, and by driver selection today).
const HOSTED_VOIP_SERVERS = {
  ringcentral: "sip.ringcentral.com",
  twilio: "sip-1042-sip.twilio.com",
  vonage: "sip.nexmo.com",
  plivo: "sip.plivo.com",
  thinq: "sip.thinq.com",
  flowroute: "sip.flowroute.com",
  myexotel: "voip.myexotel.com",
  asterisk: "",
  freepbx: "",
  generic: "",
  sim: "sim.local",
};

function voipComplete(v) {
  if (!v || typeof v !== "object") return false;
  if (!v.provider) return false;
  if (HOSTED_VOIP_SERVERS[v.provider]) return !!(v.username && v.sipPassword);
  return !!(v.server && v.username && v.sipPassword);
}

// In-process call session store. Keyed by portal + session id so several
// portal instances in one process stay isolated in tests.
const CALL_SESSIONS = new Map();
function sessionKey(portalId, id) {
  return portalId + ":" + id;
}

function killSessionsFor(portalId) {
  for (const key of Array.from(CALL_SESSIONS.keys())) {
    if (key.startsWith(portalId + ":")) CALL_SESSIONS.delete(key);
  }
}

function getSession(portalId, id) {
  return CALL_SESSIONS.get(sessionKey(portalId, id)) || null;
}

function getSessionsFor(portalId) {
  const out = [];
  for (const [key, s] of CALL_SESSIONS.entries()) {
    if (key.startsWith(portalId + ":")) out.push(s);
  }
  return out;
}

function failSession(s, message) {
  s.status = "error";
  s.error = message;
  s.endedAt = Date.now();
  return s;
}

const SIP_TRUNK_PROVIDERS = (provider) =>
  provider && !HOSTED_VOIP_SERVERS[provider] ? true : false;

// Simulated trunk - rings, waits, then "connects" a silent line. Never bills.
async function dialViaSim(ctx, session) {
  session.status = "ringing";
  session.providerLabel = "Simulator (dry-run)";
  setTimeout(() => {
    if (session.status === "ringing") {
      session.status = "in_call";
      session.answeredAt = Date.now();
      session.sim = { notes: "Simulated call. The WSS media channel is the next milestone - until then this line is audio-silent." };
    }
  }, 400);
  return session;
}

// Twilio driver - Programmable Voice over REST. This is the AUTOMATIC trunk:
// nobody answers anything; the portal's /twiml/<id> answers the line and plays
// the pitch. Per-customer keys: settings.appClientId = Account SID,
// settings.appClientSecret = Auth Token, settings.number = their verified
// Twilio caller-id number.
async function dialViaTwilio(ctx, session, settings) {
  const fet = ctx.fetch || fetch;
  const sid = String(settings.appClientId || "").trim();
  const tok = String(settings.appClientSecret || "").trim();
  const base = String(ctx.baseUrl || ("https://" + (ctx.env.PUBLIC_BASE_URL || "portal.local"))).replace(/\/+$/, "");
  if (!sid || !tok) {
    return failSession(session, "Twilio Account SID / Auth Token missing - set them once on the customer's VOIP settings.");
  }
  if (!settings.number) {
    return failSession(session, "Twilio caller-id number missing - set it once on the customer's VOIP settings.");
  }
  const from = normalizeNumber(settings.number);
  const to = session.destination;
  let resp;
  try {
    resp = await fet(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Calls.json`, {
      method: "POST",
      headers: { Authorization: "Basic " + Buffer.from(sid + ":" + tok).toString("base64"), "Content-Type": "application/x-www-form-urlencoded" },
      body: encode({
        To: to,
        From: from,
        Url: `${base}/twiml/${session.id}`,
        Timeout: "30",
        StatusCallback: `${base}/api/twilio-status`,
        StatusCallbackEvent: "initiated ringing answered completed",
      }),
    });
  } catch (e) {
    return failSession(session, "Twilio call request failed: " + e.message);
  }
  if (!resp.ok) {
    let detail = "";
    try { detail = (await resp.text()).slice(0, 300); } catch {}
    return failSession(session, "Twilio rejected call (HTTP " + resp.status + "): " + detail);
  }
  const j = await resp.json();
  session.status = "dialing";
  session.providerRef = String(j.sid || "");
  session.twilioSid = String(j.sid || "");
  session.providerLabel = "Twilio (REST Voice)";
  return session;
}

// Twilio status webhook -> a call session's real outcome.
function twilioWebhook(portalId, sid, status) {
  let s = null;
  for (const c of CALL_SESSIONS.values()) {
    if (c.portalId === portalId && (c.providerRef === sid || c.twilioSid === sid)) { s = c; break; }
  }
  if (!s) return null;
  const st = String(status || "").toLowerCase();
  if (st === "ringing" || st === "dialing" || st === "initiated") s.status = "dialing";
  else if (st === "answered") { s.status = "in_call"; s.answeredAt = s.answeredAt || Date.now(); }
  else if (st === "completed") { s.status = "connected"; s.endedAt = Date.now(); s.error = null; s.twilioOutcome = status; }
  else {
    s.status = "error";
    s.error = "Twilio: " + (status || "ended") + (st === "no-answer" ? " (no answer)" : st === "busy" ? " (busy)" : "");
    s.endedAt = Date.now();
    s.twilioOutcome = status;
  }
  return s;
}

// RingCentral driver - RingOut over REST (443). No SIP port on any PC.
//
// Two app-credential paths are supported, chosen by what the portal env
// provides:
//   1. RC_JWT - a pre-generated JWT assertion ("personal JWT credential")
//      created in the RC Developer Console under the app's Authentication
//      section. The console mints this token with the correct owner
//      identity, so the portal needs no private key. One env var total.
//   2. RC_CLIENT_ID + RC_CLIENT_SECRET - classic password grant; kept for
//      accounts where RingCentral still allows it.
// fetch is injectable via ctx.fetch so tests can verify request shape offlin
async function rcToken(ctx, settings) {
  const fet = ctx.fetch || fetch;
  // A customer may bring their own RingCentral connection: the keys live on
  // the customer profile (voip.appClientId/appClientSecret/appJwt) and take
  // priority over the portal-level env connection (owner's test line).
  const cust = settings || {};
  const clientId = String(cust.appClientId || ctx.env.RC_CLIENT_ID || "").trim();
  const clientSecret = String(cust.appClientSecret || ctx.env.RC_CLIENT_SECRET || "").trim();
  if (!clientId || !clientSecret) {
    throw new Error(
      "RingCentral driver needs the account's Developer-app Client ID/Secret. Enter them on the customer's VOIP settings (or set RC_CLIENT_ID / RC_CLIENT_SECRET on the portal) first."
    );
  }
  const assert = String(cust.appJwt || ctx.env.RC_JWT || "").trim();
  const basic = "Basic " + Buffer.from(clientId + ":" + clientSecret).toString("base64");
  if (assert) {
    const tok = await fet("https://platform.ringcentral.com/restapi/oauth/token", {
      method: "POST",
      headers: { Authorization: basic, "Content-Type": "application/x-www-form-urlencoded" },
      body: encode({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: assert }),
    });
    if (!tok.ok) throw new Error("RingCentral JWT token rejected (HTTP " + tok.status + ") - check RC_JWT / RC_CLIENT_ID / RC_CLIENT_SECRET.");
    return (await tok.json()).access_token;
  }
  const tok = await fet("https://platform.ringcentral.com/restapi/v1.0/oauth/token", {
    method: "POST",
    headers: { Authorization: basic, "Content-Type": "application/x-www-form-urlencoded" },
    body: encode({
      grant_type: "password",
      username: normalizeNumber(settings.number),
      password: settings.sipPassword,
      extension: settings.extension || "101",
    }),
  });
  if (!tok.ok) throw new Error("RingCentral password token rejected (HTTP " + tok.status + ") - check the customer's number/password.");
  return (await tok.json()).access_token;
}

async function dialViaRingCentral(ctx, session, settings) {
  // Preferred path: direct SIP soft-phone trunk (TLS + SRTP-SDES), which is
  // fully unattended (no human ever answers the origin leg). Used when the
  // customer's VOIP settings carry the SIP device credentials (username +
  // sipPassword, plus optional authId / host / port). Falls back to RingOut
  // REST for accounts that only have Developer-app credentials.
  const user = String(settings.username || "").trim();
  const sipPass = String(settings.sipPassword || "").trim();
  if (user && sipPass) {
    session.status = "dialing";
    session.providerLabel = "RingCentral SIP (TLS+SRTP)";
    session.provider = "ringcentral-sip";
    const talkMs = Math.max(2000, 1000 * Number(settings.speakSeconds || 20));
    const opts = {
      user,
      pass: sipPass,
      authId: String(settings.authId || user).trim(),
      domain: String(settings.domain || "sip.ringcentral.com"),
      proxy: String(settings.host || settings.server || "sip40.ringcentral.com"),
      port: Number(settings.port || 5096),
      number: session.destination,
      callerId: normalizeNumber(settings.number) || normalizeNumber(user),
      durationMs: talkMs,
      codec: settings.codec === "opus" ? "opus" : "pcmu",
      payloads: Array.isArray(session.audioFrames) && session.audioFrames.length ? session.audioFrames : undefined,
      segments: Array.isArray(session.audioSegments) && session.audioSegments.length ? session.audioSegments : undefined,
      listenAfterGreeting: settings.listen === true || settings.turnTaking === true || settings.listening === true,
    };
    // SBCs silently drop REGISTERs when the same device registers too
    // quickly from a fresh port - retry with backoff before giving up.
    (async () => {
      for (let attempt = 1; attempt <= 6; attempt++) {
        if (session.status === "error") return;
        const r = await sipCallOnce(opts);
        if (r.ok) {
          session.status = "connected";
          session.answeredAt = session.answeredAt || Date.now();
          session.endedAt = Date.now();
          session.outcome = r.outcome || "answered";
          session.sip = {
            steps: r.steps,
            remoteIp: (r.media || {}).remoteIp,
            remotePort: (r.media || {}).remotePort,
            srtp: !!(r.media || {}).remoteKey,
            inboundAudio: !!(r.media || {}).inboundUnlocked,
            byes: r.extra || r.last || null,
          };
          return;
        }
        session.sip = session.sip || { attempts: 0, errors: [] };
        const s = session.sip;
        s.outcome = r.outcome || "failed";
        s.attempts++;
        (s.errors || (s.errors = [])).push(r.last || "unknown");
        if (attempt < 6) await delay(3000);
      }
      session.sip = session.sip || { attempts: 0, errors: [] };
      failSession(session, "RingCentral SIP call failed after " + session.sip.attempts + " attempt(s): " + (session.sip.errors || []).join(" -> ") + (r && r.steps && r.steps.length ? " [" + r.steps.join(" -> ") + "]" : ""));
    })();
    return session;
  }

  const fet = ctx.fetch || fetch;
  const number = normalizeNumber(settings.number);
  const destination = session.destination;

  let token;
  try {
    token = await rcToken(ctx, settings);
  } catch (e) {
    return failSession(session, "RingCentral token fetch failed: " + e.message);
  }

  try {
    const ringout = await fet("https://platform.ringcentral.com/restapi/v1.0/account/~/extension/~/ring-out", {
      method: "POST",
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
      body: JSON.stringify({
        to: { phoneNumber: destination },
        from: { phoneNumber: number },
        callerId: { phoneNumber: number },
        playPrompt: false,
      }),
    });
    if (!ringout.ok) return failSession(session, "RingOut rejected (HTTP " + ringout.status + ") - check the number or account rights.");
    const j = (await ringout.json()).session || {};
    session.status = "ringing";
    session.providerRef = j.id ? String(j.id) : "";
    session.providerLabel = "RingCentral (RingOut/443)";
    if (session.providerRef && !ctx.fetch) pollRingOut(ctx, session, token, session.providerRef);
    return session;
  } catch (e) {
    return failSession(session, "RingOut request failed: " + e.message);
  }
}

function normalizeNumber(n) {
  let s = String(n || "").replace(/[^+\d]/g, "");
  if (s && !s.startsWith("+")) s = "+" + s;
  return s;
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

/* Best-effort follow-up of a launched RingOut so the dashboard reports the
 * REAL outcome (connected / no answer / invalid) instead of just "ringing".
 * Only runs when the portal is using the live network (no injected fetch),
 * so offline test suites never wait on it. */
async function pollRingOut(ctx, session, token, ringoutId) {
  try { await delay(12000); } catch {}
  const fet = ctx.fetch || fetch;
  try {
    for (let i = 0; i < 5; i++) {
      try {
        const r = await fet(`https://platform.ringcentral.com/restapi/v1.0/account/~/extension/~/ring-out/${ringoutId}`, {
          headers: { Authorization: "Bearer " + token },
        });
        if (!r.ok) { await delay(10000); continue; }
        const s = await r.json();
        const text = String((s && (s.status || s.reason || "")) || "");
        const low = text.toLowerCase();
        let outcome = null;
        if (/call connected|connected|completed|answered|success/.test(low)) outcome = { status: "connected", note: text, error: session.error || null };
        else if (/invalid|error|fail|denied|unavailable|no ?answer|not answered/.test(low)) outcome = { status: "error", note: text, error: "RingOut did not connect: " + text };
        else if (/in progress|progressing|ringing|first leg|called number|callee|originated/.test(low)) outcome = { status: "ringing", note: text, error: null };
        if (outcome) {
          try { Object.assign(session, { status: outcome.status, ringOutNote: outcome.note || null, error: outcome.error }); } catch {}
          if (outcome.status === "connected" || outcome.status === "error") return;
        }
      } catch {}
      await delay(12000);
    }
  } catch {}
}

function encode(obj) {
  return Object.entries(obj).map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");
}

/* Public: place a call for a customer through their configured dialer. */
async function placeCall(ctx, { customer, destination }) {
  const settings = (customer.settings || {}).voip || {};
  const d = normalizeNumber(destination);
  if (!/^\+?[0-9]{7,15}$/.test(String(d || "").replace(/\s/g, ""))) {
    throw Object.assign(new Error("Invalid destination number: " + destination), { code: "BAD_NUMBER" });
  }
  if (!voipComplete(settings)) {
    throw Object.assign(new Error("This customer has no complete dialer line configured yet (VOIP provider in the admin console)."), { code: "NO_DIALER" });
  }
  if (HOSTED_VOIP_SERVERS[settings.provider] && !LIVE_PROVIDERS.has(settings.provider)) {
    // Stub for hosted providers whose trunk driver is not live yet.
    const id = crypto.randomUUID();
    const session = {
      id,
      portalId: ctx.portalId,
      token: customer.token,
      status: "error",
      provider: settings.provider,
      providerLabel: settings.provider + " (cloud SIP registration not built yet)",
      destination: d,
      startedAt: Date.now(),
      error: "Trunk driver for '" + settings.provider + "' is not connected yet (cloud SIP register + media bridge is the next milestone). Only RingCentral (RingOut/443) and the simulator are live.",
    };
    CALL_SESSIONS.set(sessionKey(ctx.portalId, id), session);
    return session;
  }

  const id = crypto.randomUUID();
  const session = {
    id,
    portalId: ctx.portalId,
    token: customer.token,
    status: "dialing",
    provider: settings.provider || "generic",
    providerLabel: settings.provider || "Generic SIP",
    destination: d,
    mediaPath: LIVE_PROVIDERS.has(settings.provider) ? "/ws/media/" + id : null,
    startedAt: Date.now(),
  };
  CALL_SESSIONS.set(sessionKey(ctx.portalId, id), session);
  session.script = customer.persona || customer.product || null;

  // Auto-generated, never-ending script (nobody types one). Voices it for the
  // SIP path; the desktop agent receives the same text via heartbeat config.
  try {
    const lScript = learning.activeScript(customer);
    session.variantId = lScript.id;
    session.script = String((customer.settings || {}).scriptOverride || lScript.text || session.script || "");
  } catch {
    session.variantId = null;
  }
  if (settings.username && settings.sipPassword) {
    try {
      session.audioFrames = await audio.framesFor(session.script || "", { ttsKey: settings.ttsKey, ttsVoice: settings.ttsVoice });
      session.audioSegments = await audio.segmentsFor(session.script || "", { ttsKey: settings.ttsKey, ttsVoice: settings.ttsVoice });
    } catch { session.audioFrames = []; session.audioSegments = []; }
  }

  const drivers = {
    sim: () => dialViaSim(ctx, session),
    ringcentral: () => dialViaRingCentral(ctx, session, settings),
    twilio: () => dialViaTwilio(ctx, session, settings),
  };
  const fn = drivers[settings.provider];
  if (fn) {
    try {
      await fn();
    } catch (e) {
      failSession(session, "Trunk driver crashed: " + e.message);
    }
  } else {
    failSession(session, "No trunk driver for provider '" + settings.provider + "' yet.");
  }
  return session;
}

// Drivers considered "live" for hosted providers (sim is a dry-run driver).
const LIVE_PROVIDERS = new Set(["sim", "ringcentral", "twilio"]);

function hangUp(portalId, id) {
  const s = getSession(portalId, id);
  if (!s) return null;
  s.status = "completed";
  s.endedAt = Date.now();
  return s;
}

// ---------------------------------------------------------------------------
// Auto-dialer batch engine ("upload a list, press START, work for hours, press
// STOP"). Provider-agnostic: it dials whatever the customer's VOIP line is.
// ---------------------------------------------------------------------------
const BATCHES = new Map();
const TERMINAL = new Set(["connected", "completed", "error", "failed", "canceled", "no-answer", "busy"]);

function batchSummary(b) {
  return {
    id: b.id,
    running: b.running,
    current: b.current || null,
    done: b.results.length,
    total: b.total,
    results: b.results,
    startedAt: b.startedAt,
    endedAt: b.endedAt || null,
  };
}

async function startBatch(ctx, customer, numbers) {
  const list = (Array.isArray(numbers) ? numbers : [])
    .map((n) => normalizeNumber(String(n || "").trim()))
    .filter((n) => /^\+?[0-9]{7,15}$/.test(String(n).replace(/\s/g, "")));
  if (!list.length) throw Object.assign(new Error("No valid numbers to call"), { code: "NO_NUMBERS" });
  const prev = BATCHES.get(customer.token);
  if (prev && prev.running) return batchSummary(prev);
  const batch = {
    token: customer.token,
    portalId: ctx.portalId,
    id: crypto.randomUUID(),
    running: true,
    stopRequested: false,
    cursor: 0,
    total: list.length,
    startedAt: Date.now(),
    results: [],
    current: null,
    currentSession: null,
    customer,
  };
  BATCHES.set(customer.token, batch);
  batchPump(ctx, batch, list).catch(() => {
    batch.running = false;
    batch.endedAt = Date.now();
  });
  return batchSummary(batch);
}

async function batchPump(ctx, batch, list) {
  const retries = Math.max(0, Math.min(5, Number((batch.customer.settings || {}).callRetries || 2) || 2));
  for (let i = 0; i < list.length; i++) {
    if (batch.stopRequested) break;
    batch.cursor = i;
    const dest = list[i];
    let outcome = "failed";
    for (let attempt = 0; attempt <= retries; attempt++) {
      if (batch.stopRequested) break;
      let s = null;
      try {
        s = await placeCall(ctx, { customer: batch.customer, destination: dest });
      } catch (e) {
        outcome = "error";
        if (attempt < retries) { await delay(5000 * (attempt + 1)); continue; }
        batch.results.push({ number: dest, status: "error", error: e.message, at: Date.now() });
        outcome = "error";
        break;
      }
      batch.current = { id: s.id, number: dest, status: s.status };
      batch.currentSession = s;
      const timeoutMs = 1000 * 60 * (s.provider === "sim" ? 1 : 25);
      await waitForFinal(timeoutMs, s);
      const ok = s.status === "connected" || s.status === "completed" || s.status === "in_call";
      if (ok) {
        outcome = s.outcome || "connected";
        batch.results.push({ number: dest, status: "connected", outcome, error: null, at: Date.now() });
        batch.current = null;
        batch.currentSession = null;
        break;
      }
      const o = String(s.outcome || (s.sip && s.sip.outcome) || "").toLowerCase();
      outcome = o === "busy" || o === "no-answer" ? o : "failed";
      const retryable = outcome !== "no-answer" && outcome !== "busy";
      if (attempt < retries && retryable) {
        await delay(5000 * (attempt + 1));
        continue;
      }
      batch.results.push({ number: dest, status: outcome, error: ok ? null : s.error, at: Date.now() });
      batch.current = null;
      batch.currentSession = null;
      break;
    }
    try { persistBatch(ctx, batch); } catch {}
    await delay(800);
  }
  batch.running = false;
  batch.endedAt = Date.now();
  try { persistBatch(ctx, batch); } catch {}
  return batchSummary(batch);
}

/** Persist the latest batch snapshot on the customer so /status works from
 *  any portal instance (cloud runs are multi-instance). */
async function persistBatch(ctx, batch) {
  const db = ctx.db;
  if (!db || !batch || !batch.customer) return;
  await updateCustomer(db, batch.customer.token, { settings: { batch: batchSummary(batch) } });
}

async function waitForFinal(timeoutMs, session) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const st = session.status || "";
    if (TERMINAL.has(st)) return st;
    if (st === "in_call" && session.provider === "sim") return st;
    await delay(3000);
  }
  return session.status || "";
}

function stopBatch(portalId, token) {
  const b = BATCHES.get(token);
  if (!b) return null;
  b.stopRequested = true;
  if (b.currentSession && b.portalId) hangUp(b.portalId, b.currentSession.id);
  b.running = false;
  b.endedAt = Date.now();
  return batchSummary(b);
}

function getBatch(token) {
  const b = BATCHES.get(token);
  return b ? batchSummary(b) : null;
}

/* Dev diagnostic: does an account's credentials register as a SIP soft-phone
 * from THIS host? Used to prove unattended-call capability on a provider. */
const md5 = (s) => crypto.createHash("md5").update(s, "ascii").digest("hex");
function sipRegisterOnce(o) {
  const user = String(o.user || "");
  const pass = String(o.pass || "");
  const authId = String(o.authId || user);
  const ext = String(o.ext || "");
  const domain = String(o.domain || "sip.ringcentral.com").replace(/:\d+$/, "");
  const proxy = String(o.host || "sip40.ringcentral.com");
  const port = Number(o.port || 5096);
  const proto = o.proto === "tcp" ? "tcp" : "tls";
  return new Promise((resolve) => {
    const aor = `sip:${user}@${domain}`;
    const contact = `sip:${user}@${proxy}`;
    const steps = [];
    let nonce = null, qop = null, authed = false, realm = null, challenge = "";
    const authUser = authId || user;
    const buildMsg = (cseq) => {
      const lines = [
        "REGISTER " + aor + " SIP/2.0",
        `Via: SIP/2.0/${proto.toUpperCase()} ${proxy};branch=z9hG4bK` + crypto.randomBytes(6).toString("hex"),
        "Max-Forwards: 70",
        "From: <" + contact + ">;tag=" + crypto.randomBytes(6).toString("hex"),
        "To: <" + contact + ">",
        "Call-ID: " + crypto.randomBytes(8).toString("hex"),
        "CSeq: " + cseq + " REGISTER",
        "Contact: <" + contact + ">",
        "Expires: 300",
        "User-Agent: MagicDialer-SIP/0.1",
      ];
      if (authed && nonce) {
        const HA1 = md5(`${authUser}:${domain}:${pass}`);
        let resp;
        if (qop) {
          const nc = "00000001", cn = crypto.randomBytes(4).toString("hex");
          resp = md5(`${HA1}:${nonce}:${nc}:${cn}:${qop}:${md5("REGISTER:" + aor)}`);
          lines.push(`Authorization: Digest username="${authUser}", realm="${realm || domain}", nonce="${nonce}", uri="${aor}", qop=${qop}, nc=${nc}, cnonce="${cn}", response="${resp}"`);
        } else {
          resp = md5(`${HA1}:${nonce}:${md5("REGISTER:" + aor)}`);
          lines.push(`Authorization: Digest username="${authUser}", realm="${realm || domain}", nonce="${nonce}", uri="${aor}", response="${resp}"`);
        }
      }
      lines.push("Content-Length: 0", "", "");
      return lines.join("\r\n");
    };
    let settled = false;
    const done = (ok, line, extra) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardGate);
      try { sock.destroy(); } catch {}
      resolve({ ok, host: proxy, port, proto, user, authId: authUser, ext, domain, steps, pass: "(hidden)", last: line, extra });
    };
    const onConn = () => sock.write(buildMsg(1));
    const sock = proto === "tls"
      ? tls.connect({ port, host: proxy, servername: proxy.split(":")[0], rejectUnauthorized: false }, onConn)
      : net.connect(port, proxy, onConn);
    const hardGate = setTimeout(() => done(false, "no response (network or firewall)"), 11000);
    sock.setTimeout(8000);
    let buf = "";
    sock.on("data", (d) => {
      buf += d.toString("ascii");
      if (!buf.includes("\r\n\r\n")) return;
      const txt = buf; buf = "";
      const line = txt.split("\r\n")[0].trim();
      steps.push(line);
      const m = txt.match(/[Rr]eal[mM]\s*=\s*"?([^"\s,]+)"?/);
      if (m) realm = m[1];
      if (/401|407/.test(line) && !authed) {
        authed = true;
        nonce = (txt.match(/[Nn]once\s*=\s*"?([^"\s,]+)"?/) || [])[1] || null;
        qop = (txt.match(/[Qq]op\s*=\s*"?([^"\s,]+)"?/) || [])[1] || null;
        challenge = String(txt.match(/WWW-Authenticate[^\r\n]*/i) || txt.match(/Proxy-Authenticate[^\r\n]*/i) || [""])[0];
        if (nonce) { setTimeout(() => sock.write(buildMsg(2)), 200); }
        else done(false, line + " (no nonce in challenge)", { challenge });
      } else if (/200 OK/.test(line)) done(true, line);
      else if (/401|407/.test(line) && authed) done(false, line + " (auth rejected)");
      else if (/^(403|404|484)/.test(line)) done(false, line);
    });
    sock.on("timeout", () => done(false, "no response (network or firewall)"));
    sock.on("error", (e) => done(false, "connection error: " + e.message));
  });
}

/** Dev diagnostic: place one full RC SIP call and return the raw result.
 *  Retries a few times to ride through SBC registration cooldowns. */
async function sipCallRetry(opts, attempts = 5, gapMs = 3500) {
  let r = null;
  for (let i = 0; i < attempts; i++) {
    r = await sipCallOnce(opts);
    if (r.ok) return r;
    if (i < attempts - 1) await delay(gapMs);
  }
  return r;
}

module.exports = {
  HOSTED_VOIP_SERVERS,
  voipComplete,
  placeCall,
  getSession,
  getSessionsFor,
  killSessionsFor,
  hangUp,
  twilioWebhook,
  sipRegisterOnce,
  sipCallRetry,
  startBatch,
  stopBatch,
  getBatch,
};