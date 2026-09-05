/**
 * Internet lead finder for the portal.
 *
 * On command (admin button, or the auto-scheduler) the portal searches the
 * web for companies that likely buy the customer's product/service, so the
 * customer's AI then has a real call list to work from.
 *
 * Providers (configured by env on the portal host):
 *   - SEARCH_ENGINE=serper   + SEARCH_API_KEY          -> Serper.dev (Google)
 *   - SEARCH_ENGINE=serpapi  + SEARCH_API_KEY          -> SerpAPI
 *   - SEARCH_ENGINE=bing                                 -> Bing HTML (no key)
 *   - default ("auto"): DuckDuckGo HTML, falling back to Bing HTML when DDG
 *     rate-limits (it frequently serves an "anomaly" page to cloud IPs).
 *   - SEARCH_FIXED_JSON      (optional, test mode)      -> deterministic results
 *
 * Dependency-free (node https only), so it works on any free host.
 */
const https = require("node:https");
const http = require("node:http");

const UAS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
];

function getText(url, timeoutMs = 15000, ua = UAS[0]) {
  return new Promise((resolve) => {
    const lib = url.startsWith("https") ? https : http;
    const req = lib.get(url, {
      headers: {
        "User-Agent": ua,
        "Accept-Language": "en-US,en;q=0.9",
        Accept: "text/html,application/json,*/*",
      },
    }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    });
    req.on("timeout", () => { req.destroy(); resolve(""); });
    req.setTimeout(timeoutMs);
    req.on("error", () => resolve(""));
  });
}

function decodeEntities(s) {
  return String(s)
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, " ")
    .replace(/&#x27;/g, "'");
}

function stripTags(s) {
  return String(s).replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}

/** Build a focused search query for the customer's product/service. */
function searchQueryFor(product, extraKeywords = "") {
  const words = String(product || "")
    .replace(/[^\p{L}\p{N} ]/gu, " ")
    .split(/\s+/).filter((w) => w.length > 2 && !/^(and|for|the|your|our|with|to|of|in|we|us|on|at|by|is|are|a|an)$/i.test(w));
  const core = words.slice(0, 6).join(" ");
  const kw = extraKeywords ? ` ${extraKeywords}` : " company OR service providers who need";
  return `${core}${kw} -jobs -careers -recruiting`.trim();
}

function brandFromTitle(title) {
  if (!title) return "";
  const parts = String(title).split(/[|–—-]/)[0].trim();
  const words = parts.split(/\s+/).slice(0, 6).join(" ");
  return words;
}

/** Turn a DuckDuckGo /uddg or Bing ck/a redirect link into the real URL. */
function decodeRedirect(href) {
  const h = String(href || "");
  // DuckDuckGo: ...?uddg=<urlencoded>
  const uddg = h.match(/[?&]uddg=([^&]+)/);
  if (uddg) {
    try { return decodeURIComponent(uddg[1]); } catch { return ""; }
  }
  // Bing "ck/a" redirect: the destination is the base64url "u" parameter,
  // optionally prefixed with the "a1" marker (observed format: a1<base64url>).
  if (/bing\.com\/ck\/a/i.test(h)) {
    const u = h.match(/[?&]u=([^&]+)/);
    if (u) {
      try {
        let b64 = u[1].replace(/-/g, "+").replace(/_/g, "/");
        b64 = b64.replace(/^a1/, ""); // strip the "a1" marker if present
        while (b64.length % 4) b64 += "=";
        return Buffer.from(b64, "base64").toString("utf8");
      } catch { return ""; }
    }
  }
  return h;
}

const ADULT_WORDS = /\b(porn|xxx|sex|adult|escort|xnxx|xhamster|tube|hentai|milf|cam)\b/i;

function isJunkResult({ title, source, snippet }) {
  const t = String(title || "") + " " + String(source || "") + " " + String(snippet || "");
  if (/kakaku\.com|\.tistory\.com|blog\.naver\.com|zhihu\.com|merriam-webster|dictionary|support\.google|steampowered|\.twitch\.tv|fandom\.com/i.test(t)) return true;
  // Free engines sometimes serve content in unrelated languages to cloud IPs.
  if (/[\u4e00-\u9fff\u3040-\u30ff\u30a0-\u30ff\uac00-\ud7af]/.test(t)) return true;
  return /\.gov\.|wikipedia\.org|youtube\.com|amazon\.|\breddit\.com\b|whatsapp\.com|facebook\.com|instagram\.com|tiktok\.com|telegram\.org|pinterest\.com|\bquora\.com\b|stackoverflow\.com|\bromance\b/i.test(t) || ADULT_WORDS.test(t);
}

/** DuckDuckGo HTML scrape (free, but rate-limits cloud IPs). */
async function duckduckgo(query, n, ua) {
  const html = await getText(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`, 15000, ua);
  const results = [];
  const reResult = /<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)<\/a>/gi;
  const reSnippet = /class="result__snippet"[^>]*>(.*?)<\/a>/gi;

  const snips = [];
  let m;
  while ((m = reSnippet.exec(html))) snips.push(stripTags(decodeEntities(m[1])));
  let i = 0;
  while ((m = reResult.exec(html)) && results.length < n) {
    const rawHref = decodeEntities(m[1] || "");
    const href = decodeRedirect(rawHref);
    const title = stripTags(decodeEntities(m[2]));
    if (!href || href === "#" || /^\/|duckduckgo\.com|bing\.com/.test(href)) continue;
    results.push({
      company: brandFromTitle(title),
      title,
      source: href,
      snippet: snips[i++] || "",
      score: Math.max(40, 90 - results.length * 6),
    });
  }
  return results;
}

/** Bing HTML scrape - reliable from cloud IPs, no key needed. */
async function bing(query, n, ua) {
  const html = await getText(`https://www.bing.com/search?q=${encodeURIComponent(query)}&setlang=en&cc=us&count=${n}`, 15000, ua);
  const results = [];
  const chunks = String(html).split('<li class="b_algo"').slice(1);
  for (const chunk of chunks) {
    if (results.length >= n) break;
    const hrefM = chunk.match(/<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)<\/a>/);
    const pM = chunk.match(/<p[^>]*>(.*?)<\/p>/);
    if (!hrefM) continue;
    const rawHref = decodeEntities(hrefM[1] || "");
    const href = decodeRedirect(rawHref);
    if (!/^https?:\/\//i.test(href) || /(bing\.com|microsoft\.com|go\.microsoft)/i.test(href)) continue;
    const title = stripTags(decodeEntities(hrefM[2]));
    if (!title) continue;
    const snippet = pM ? stripTags(decodeEntities(pM[1])) : "";
    if (isJunkResult({ title, source: href, snippet })) continue;
    results.push({
      company: brandFromTitle(title),
      title,
      source: href,
      snippet,
      score: Math.max(40, 90 - results.length * 6),
    });
  }
  return results;
}

/** Generic JSON search via Serper.dev (Google). */
async function serper(query, n) {
  const key = process.env.SEARCH_API_KEY;
  if (!key) return [];
  const body = JSON.stringify({ q: query, num: Math.min(n, 10) });
  const out = await new Promise((resolve) => {
    const req = https.request("https://google.serper.dev/search", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-KEY": key, "Content-Length": Buffer.byteLength(body) },
    }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    });
    req.on("error", () => resolve(""));
    req.setTimeout(15000, () => req.destroy());
    req.write(body);
    req.end();
  });
  try {
    const j = JSON.parse(out);
    return (j.organic || []).slice(0, n).map((r) => ({
      company: brandFromTitle(r.title),
      title: r.title || r.link || "",
      source: r.link || "",
      snippet: r.snippet || "",
      score: (r.position || 10) <= 3 ? 90 : 70,
    }));
  } catch {
    return [];
  }
}

/** Generic JSON search via SerpAPI. */
async function serpapi(query, n) {
  const key = process.env.SEARCH_API_KEY;
  if (!key) return [];
  const url = `https://serpapi.com/search.json?engine=google&api_key=${encodeURIComponent(key)}&num=${Math.min(n, 10)}&q=${encodeURIComponent(query)}`;
  const out = await getText(url);
  try {
    const j = JSON.parse(out);
    return (j.organic_results || []).slice(0, n).map((r) => ({
      company: brandFromTitle(r.title),
      title: r.title || r.link || "",
      source: r.link || "",
      snippet: r.snippet || "",
      score: (r.position || 10) <= 3 ? 90 : 70,
    }));
  } catch {
    return [];
  }
}

/**
 * Search the internet for leads relevant to the customer's product.
 * Returns an array of { company, title, source, snippet, score }.
 */
async function searchLeads({ product, extraKeywords = "", count = 12, skipCache } = {}) {
  if (!String(product || "").trim()) return [];
  const engine = (process.env.SEARCH_ENGINE || "auto").toLowerCase();
  const n = Math.max(3, Math.min(count || 12, 25));

  if (process.env.SEARCH_FIXED_JSON) {
    try {
      const fixed = JSON.parse(process.env.SEARCH_FIXED_JSON);
      return fixed.slice(0, n).map((f, i) => ({
        company: f.company || brandFromTitle(f.title || f.source),
        title: f.title || f.source,
        source: f.source || "",
        snippet: f.snippet || "",
        score: f.score != null ? f.score : 60,
        id: f.id,
      }));
    } catch {
      return [];
    }
  }

  const query = searchQueryFor(product, extraKeywords);

  /**
   * Free search engines (DuckDuckGo/Bing) routinely serve bot-protection
   * pages to cloud IPs, and responses vary by request. Retry across several
   * user-agents/engines so a real results page is found in most attempts.
   */
  const attempts = [];
  if (engine === "serper") return await serper(query, n);
  if (engine === "serpapi") return await serpapi(query, n);

  const engines = engine === "bing" ? ["bing", "bing", "bing"] : engine === "ddg" ? ["ddg", "ddg", "ddg"] : ["ddg", "bing", "ddg", "bing"];
  const dedupe = new Map();
  for (const eng of engines) {
    for (const ua of UAS) {
      if (attempts.length >= engines.length * 2) break;
      attempts.push(eng);
      try {
        const list = eng === "bing" ? await bing(query, n, ua) : await duckduckgo(query, n, ua);
        for (const lead of list) {
          if (lead && lead.source && !dedupe.has(lead.source)) dedupe.set(lead.source, lead);
        }
        if (dedupe.size >= Math.min(5, n)) break;
      } catch { /* try next combination */ }
    }
    if (dedupe.size >= Math.min(5, n)) break;
  }
  return Array.from(dedupe.values()).slice(0, n);
}

module.exports = { searchLeads, searchQueryFor, brandFromTitle, stripTags, decodeEntities, duckduckgo, bing, decodeRedirect, isJunkResult };