/**
 * Internet lead finder for the portal.
 *
 * On command (admin button, or the auto-scheduler) the portal searches the
 * web for companies that likely buy the customer's product/service, so the
 * customer's AI then has a real call list to work from.
 *
 * Providers (in order of preference, configured by env on the portal host):
 *   - SEARCH_ENGINE=serper   + SEARCH_API_KEY          -> Serper.dev (Google)
 *   - SEARCH_ENGINE=serpapi  + SEARCH_API_KEY          -> SerpAPI
 *   - default: DuckDuckGo HTML (no key needed, subject to their rate limits)
 *   - SEARCH_FIXED_JSON      (optional, test mode)      -> deterministic results
 *
 * Dependency-free (node https only), so it works on any free host.
 */
const https = require("node:https");
const http = require("node:http");

function getText(url, timeoutMs = 15000) {
  return new Promise((resolve) => {
    const lib = url.startsWith("https") ? https : http;
    const req = lib.get(url, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
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

/** DuckDuckGo HTML scrape (free, no key). Returns up to `n` results. */
async function duckduckgo(query, n) {
  const html = await getText(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`);
  const results = [];
  const re = /<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)<\/a>|<a[^>]*class="result__a"[^>]*>(.*?)<\/a>[^>]*?href="?([^"\s>]+)/gi;
  const reLabel = /class="result__a"[^>]*>(.*?)<\/a>/gi;
  const reSnippet = /class="result__snippet"[^>]*>(.*?)<\/a>/gi;
  const reResult = /<a[^>]*result__a[^>]*href="([^"]+)"[^>]*>(.*?)<\/a>/gi;

  let m;
  const snips = [];
  while ((m = reSnippet.exec(html))) snips.push(stripTags(decodeEntities(m[1])));
  let i = 0;
  while ((m = reResult.exec(html)) && results.length < n) {
    const href = decodeEntities(m[1] || "");
    const title = stripTags(decodeEntities(m[2]));
    if (!href || href === "#" || /duckduckgo\.com/.test(href)) continue;
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
  const engine = (process.env.SEARCH_ENGINE || "ddg").toLowerCase();
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
      }));
    } catch {
      return [];
    }
  }

  const query = searchQueryFor(product, extraKeywords);
  try {
    if (engine === "serper") return await serper(query, n);
    if (engine === "serpapi") return await serpapi(query, n);
    return await duckduckgo(query, n);
  } catch {
    return [];
  }
}

module.exports = { searchLeads, searchQueryFor, brandFromTitle, stripTags, decodeEntities };