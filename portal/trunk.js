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
  const clientId = ctx.env.RC_CLIENT_ID || "";
  const clientSecret = ctx.env.RC_CLIENT_SECRET || "";
  if (!clientId || !clientSecret) {
    throw new Error(
      "RingCentral driver needs the account's Developer-app Client ID/Secret. Set RC_CLIENT_ID / RC_CLIENT_SECRET on the portal (or paste a personal JWT credential) first."
    );
  }
  const assert = (ctx.env.RC_JWT || "").trim();
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

  const drivers = {
    sim: () => dialViaSim(ctx, session),
    ringcentral: () => dialViaRingCentral(ctx, session, settings),
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
const LIVE_PROVIDERS = new Set(["sim", "ringcentral"]);

function hangUp(portalId, id) {
  const s = getSession(portalId, id);
  if (!s) return null;
  s.status = "completed";
  s.endedAt = Date.now();
  return s;
}

module.exports = {
  HOSTED_VOIP_SERVERS,
  voipComplete,
  placeCall,
  getSession,
  getSessionsFor,
  killSessionsFor,
  hangUp,
};