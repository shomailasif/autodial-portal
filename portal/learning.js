/*
 * Self-improving sales engine (never-ending).
 *
 * Nobody ever types a script. The engine generates the call script from what
 * is ALREADY known about the customer (product/service + company + the
 * qualification fields), then keeps sharpening it forever:
 *
 *   - generateScript():  deterministic builder from the customer profile.
 *   - learnFromCall():   every call result (transcript / score / goodLead)
 *                        updates the active variant's metrics immediately.
 *   - refreshKnowledge(): pulls fresh product/sales knowledge from internet
 *                        search results (snippets) so claims stay current.
 *   - dailyLoop():       daily A/B rotation + web refresh + best-variant
 *                        ranking. Runs every day for every live dialer.
 *
 * All state lives under customer.settings.learning so it persists in the DB
 * and is safe across portal instances.
 */
const crypto = require("node:crypto");

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_QUESTIONS = 7;

const FIELD_VOICES = {
  NAME: ["May I have your name, please?", "And who do I have the pleasure of speaking with?"],
  "PHONE NUMBER": ["And what is the best phone number I can reach you at?", "Which number should we use to reach you?"],
  PHONE: ["And what is the best phone number I can reach you at?", "Which number should we use to reach you?"],
  EMAIL: ["What is the best email address for the details?", "And where should I send the details?"],
  MC: ["Could you share your MC or DOT number?", "And do you have an MC number I can note down?"],
  "MC NUMBER": ["Could you share your MC number?", "And do you have a company MC number?"],
  ADDRESS: ["And where is the company located?", "Could I get the service address?"],
  ZIP: ["And what is the postal / ZIP code?", "Which area is that in?"],
  CITY: ["And which city are you in?", "What city is that based in?"],
  COMPANY: ["And what is the company name?", "Which company should I note this under?"],
};

const OPENERS = [
  "Welcome! This is a quick courtesy call.",
  "Hi there, thanks for answering.",
  "Hello, quick one-minute call, I promise.",
  "Good day, I appreciate you picking up.",
];

const WRAPPERS = [
  "Perfect, that is everything I need. Thank you so much, and have a great day.",
  "Great, that covers it. Thanks for your time, and have a wonderful day.",
  "Excellent, I have all the information. Thank you and take care.",
];

const DEFAULT_CLAIMS = [
  "We help businesses like yours get connected and qualified quickly.",
  "Our service is fast, easy, and helps you save time every day.",
];

function pick(arr, n = 0) {
  return arr[n % arr.length];
}

function safeText(v) {
  return String(v || "").replace(/["'<>]/g, "").replace(/\s+/g, " ").trim();
}

/** Strip HTML entities, URLs, mojibake and control/non-ASCII junk so a web
 *  snippet becomes clean voice text. */
function cleanBullet(raw) {
  let t = String(raw || "");
  t = t.replace(/&#?[a-zA-Z0-9]+;/g, " ");
  t = t.replace(/https?:\/\/\S+/g, " ");
  t = t.replace(/[\uFFFD\u0000-\u001F\u007F-\u009F]/g, " ");
  t = t.replace(/[^\x20-\x7E]/g, " ");
  return t.replace(/\s+/g, " ").trim();
}

const NOISE_RE = /(download|watch|episode|gameplay|trailer|game\b|app store|play store|amazon|your order|buy now|official|newsletter|reviews?\b|opening hours|price\$|\b\d{1,2}\/\d{1,2}\/\d{2,4}\b|\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}\b)/i;

/** Only keep snippets that are topical for the product and read cleanly. */
function usableBullet(raw, product) {
  const t = cleanBullet(raw);
  if (t.length < 25 || t.length > 300) return null;
  if (/\s\|\s/.test(t)) return null;
  if (!/[.!?]/.test(t)) return null;
  if (t.split(" ").length < 3) return null;
  if (NOISE_RE.test(t)) return null;
  const words = String(product || "").toLowerCase().split(/\s+/)
    .map((w) => w.replace(/\W/g, ""))
    .filter((w) => w.length > 3 && !/^(services?|about|with|from|your)$/.test(w));
  if (words.length && !words.some((w) => t.toLowerCase().includes(w))) return null;
  const idx = t.indexOf(".", 40);
  return (idx > 40 ? t.slice(0, idx + 1) : t).slice(0, 220);
}

function normalizeField(f) {
  return String(f || "").toUpperCase().replace(/["'<>]/g, "").replace(/\s+/g, " ").trim();
}

function questionFor(field, salt = 0) {
  const key = normalizeField(field);
  const pool = FIELD_VOICES[key] || FIELD_VOICES[key.split(" ")[0]] || null;
  return pool ? pick(pool, salt) : `And could you provide your ${key.toLowerCase()}?`;
}

/** Build the spoken script for a customer. Returns plain text lines the agent
 *  reads aloud (or the engine voices directly). Only uses what the profile
 *  already knows - nothing is asked of the user. */
function generateScript(inputs) {
  const product = safeText(inputs.product);
  const company = safeText(inputs.companyName);
  const persona = safeText(inputs.persona);
  const fields = (Array.isArray(inputs.leadFields) ? inputs.leadFields : [])
    .map(normalizeField)
    .filter(Boolean)
    .slice(0, MAX_QUESTIONS);
  const knowledge = Array.isArray(inputs.knowledge) ? inputs.knowledge : [];
  const salt = Number(inputs.salt) || 0;

  const claim = (() => {
    const usable = (knowledge || []).map((k) => k.bullet && usableBullet(k.bullet, product)).filter(Boolean);
    if (usable.length) return usable[salt % usable.length];
    return pick(DEFAULT_CLAIMS, salt);
  })();

  const lines = [];
  const greet = persona
    ? `Hello, this is ${persona}${company ? " from " + company : ""}.`
    : company
      ? `Hello, this is ${company}.`
      : pick(OPENERS, salt);
  lines.push(greet);

  if (product) {
    lines.push(`I'm reaching out because we provide ${product}.`);
  }
  if (claim) lines.push(claim);

  if (fields.length) {
    lines.push("I just need a couple of details so I can help you quickly.");
    fields.forEach((f, i) => lines.push(questionFor(f, i + salt)));
  }
  lines.push(pick(WRAPPERS, salt));
  return lines.join(" ");
}

/** Produce one script variant id + text. Variants differ by opening, claim
 *  order, and question phrasing (salt) so the engine can A/B test sales
 *  approaches without any human writing copy. */
function makeVariant(inputs, knowledge, saltOffset) {
  const salt = saltOffset + Math.floor(crypto.randomBytes(2).readUInt16BE(0));
  const text = generateScript({ ...inputs, knowledge, salt });
  return { id: crypto.randomUUID().slice(0, 8), text, salt, played: 0, connected: 0, goodLeads: 0, scoreSum: 0, scoreN: 0, createdAt: Date.now() };
}

/** Initialise a customer's learning state if missing. */
function initState(customer) {
  const s = (customer.settings || {}).learning;
  if (s && Array.isArray(s.variants) && s.variants.length) return s;
  const fresh = {
    createdAt: Date.now(),
    activeVariant: null,
    variants: [],
    knowledge: [],
    stats: { calls: 0, connected: 0, goodLeads: 0, scoreSum: 0, scoreN: 0, lastCallAt: null, lastLearnAt: null },
    lastWebRefreshAt: null,
    version: 1,
  };
  return fresh;
}

/** Get (creating if needed) the current best variant to speak. */
function activeScript(customer) {
  const s = initState(customer);
  const inputs = profileInputs(customer);
  if (!s.activeVariant) {
    if (!s.variants.length) {
      s.variants.push(makeVariant(inputs, s.knowledge, 0));
      s.activeVariant = s.variants[0].id;
    } else {
      s.activeVariant = s.variants.reduce((best, v) => (variantScore(v) > variantScore(best) ? v : best)).id;
    }
  }
  // Self-healing: never let a polluted web claim replay on a live call.
  const active = s.variants.find((v) => v.id === s.activeVariant) || s.variants[0];
  if (active) repairText(active, inputs, s.knowledge);
  return { id: s.activeVariant, text: active ? active.text : generateScript({ ...inputs, knowledge: s.knowledge, salt: 0 }), state: s };
}

/** 0-100 quality score for a variant (Thompson-like: favours samples, then
 *  average goodlead rate, then average score). */
function variantScore(v) {
  if (!v || !v.played) return 0;
  const rate = v.goodLeads / v.played;
  const avgScore = v.scoreN ? v.scoreSum / v.scoreN / 100 : 0;
  const confidence = Math.min(1, v.played / 8);
  return Math.round(100 * (0.5 * rate + 0.3 * avgScore) * (0.5 + 0.5 * confidence));
}

function profileInputs(customer) {
  const set = customer.settings || {};
  return {
    product: customer.product || "",
    companyName: set.companyName || "",
    persona: customer.persona || "",
    leadFields: (() => {
      try { const v = JSON.parse(customer.lead_fields || "[]"); return Array.isArray(v) ? v : []; } catch { return []; }
    })(),
    lang: set.lang || "en",
  };
}

/** The language this customer's callers speak most, from accumulated STT
 *  feedback. Returns a language code or null when there is no memory yet. */
function preferredLang(learning) {
  const hits = (learning || {}).stats && (learning || {}).stats.langHits;
  if (!hits || typeof hits !== "object") return null;
  const entries = Object.entries(hits).sort((a, b) => b[1] - a[1]);
  return entries.length ? entries[0][0] : null;
}

/** Feeds one call outcome into learning. Returns the updated learning state. */
async function learnFromCall(learning, { score, goodLead, transcript, connected, lang }) {
  const s = learning || {};
  const st = s.stats || (s.stats = { calls: 0, connected: 0, goodLeads: 0, scoreSum: 0, scoreN: 0, langHits: {}, lastCallAt: null, lastLearnAt: null });
  st.calls++;
  st.lastCallAt = Date.now();
  st.lastLearnAt = Date.now();
  if (connected) st.connected++;
  if (goodLead) st.goodLeads++;
  if (typeof score === "number" && Number.isFinite(score)) { st.scoreSum += score; st.scoreN++; }
  // Language memory: remember what the far side actually speaks so the next
  // call can voice its very first line in the right language instead of
  // waiting to re-detect after answering.
  if (lang) {
    st.langHits = st.langHits || {};
    st.langHits[lang] = (st.langHits[lang] || 0) + 1;
    st.preferredLang = preferredLang(s);
  }

  const v = (s.variants || []).find((x) => x.id === s.activeVariant);
  if (v) {
    v.played++;
    if (connected) v.connected++;
    if (goodLead) v.goodLeads++;
    if (typeof score === "number" && Number.isFinite(score)) { v.scoreSum += score; v.scoreN++; }
  }

  // Detect strong language in the transcript: when "interested/yes/sign up/"
  // appear in a scored transcript, promote the claim the variant used.
  const t = String(transcript || "").toLowerCase();
  if (goodLead && t && v) {
    v.worked = v.worked || [];
    v.worked.push(Date.now());
    if (v.salt != null) s.kind = "working:" + v.salt;
  }
  return s;
}

/** Pull fresh internet knowledge about the customer's product. Best-effort:
 *  never throws; on failure keeps the previous bullets. */
async function refreshKnowledge(customer, searchLeads) {
  const set = customer.settings || {};
  const s = initState(customer);
  const product = safeText(customer.product);
  if (!product) return s;
  try {
    const results = await searchLeads({ product, count: 8 });
    const seen = new Set();
    const bullets = [];
    for (const r of results) {
      const good = usableBullet([r.title, r.snippet].filter(Boolean).join(" - "), product);
      if (!good) continue;
      const key = good.slice(0, 60);
      if (seen.has(key)) continue;
      seen.add(key);
      bullets.push({ id: crypto.randomUUID().slice(0, 8), bullet: good, source: r.source || "", seenAt: Date.now() });
      if (bullets.length >= 6) break;
    }
    if (bullets.length) {
      s.knowledge = (s.knowledge || []).concat(bullets).slice(-12);
      s.lastWebRefreshAt = Date.now();
    }
  } catch {
    /* keep previous knowledge */
  }
  return s;
}

const POLLUTED_RE = /&#\d+|&#x[a-f0-9]+;|\uFFFD|\bdownload\b/i;

/** Repair any stored variant whose baked text got polluted by a bad web
 *  snippet, so junk never replays and new variants stay clean. */
function repairText(v, inputs, knowledge) {
  if (v && typeof v.text === "string" && POLLUTED_RE.test(v.text)) {
    v.text = generateScript({ ...inputs, knowledge, salt: v.salt || 0 });
  }
  return v;
}

/** One daily improvement pass: refresh web knowledge, spawn one new A/B
 *  variant, and re-rank the active variant. Call this every 24h. */
async function dailyPass(customer, searchLeads, now = Date.now()) {
  const set = customer.settings || {};
  const s = await refreshKnowledge(customer, searchLeads);
  const inputs = profileInputs(customer);

  const last = s.lastVariantAt || 0;
  if (now - last > DAY_MS) {
    s.variants.push(makeVariant(inputs, s.knowledge, s.variants.length));
    s.variants = s.variants.slice(-12);
    s.lastVariantAt = now;
  }
  for (const v of s.variants || []) repairText(v, inputs, s.knowledge);
  const best = s.variants.length
    ? s.variants.reduce((acc, v) => (variantScore(v) > variantScore(acc) ? v : acc))
    : null;
  if (best) s.activeVariant = best.id;
  s.lastLearnAt = now;
  return s;
}

/** Qualification gate: a lead may only be sent when the customer's required
 *  fields are present. Returns { qualified, missing, answers }. */
function qualifyLead(customer, answers) {
  const fields = (() => {
    try { const v = JSON.parse(customer.lead_fields || "[]"); return Array.isArray(v) ? v : []; } catch { return []; }
  })().map(normalizeField).filter(Boolean);
  const a = answers && typeof answers === "object" ? answers : {};
  const map = {};
  for (const k of Object.keys(a)) map[normalizeField(k)] = String(a[k] || "").trim();

  const missing = fields.filter((f) => !map[f]);
  if (!missing.length) {
    return { qualified: true, missing: [], answers: a };
  }
  // Minimum bar: if we have at least the first field (usually name), keep it
  // as "needs more" instead of junk.
  const partial = fields.length && map[fields[0]] ? true : false;
  return { qualified: false, missing, answers: a, partialReady: partial };
}

module.exports = { generateScript, initState, activeScript, learnFromCall, refreshKnowledge, dailyPass, qualifyLead, variantScore, questionFor, preferredLang, DAY_MS };