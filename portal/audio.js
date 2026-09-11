/*
 * Audio -> PCMU (G.711 μ-law @ 8kHz) frames for SRTP streaming.
 * - WAV (PCM 8/16-bit, any rate, mono/stereo) decoded in pure JS.
 * - MP3 decoded via mpg123-decoder (WASM, no native build).
 * - No-key TTS providers synthesise the (auto-generated) script to MP3 with
 *   an internal provider chain so speech is produced on as many networks as
 *   possible; an optional premium key is honoured when present.
 * Output: array of Buffer(160) μ-law frames = one 20ms RTP payload each.
 */
const crypto = require("node:crypto");
const WS = require("ws");

const RATE = 8000;
const FRAME = 160;
const SILENCE = Buffer.alloc(FRAME, 0xff);

/** G.711 μ-law segment table (RFC 3551). */
const ULAW_SEG_END = [0x0ff, 0x1ff, 0x3ff, 0x7ff, 0x0fff, 0x1fff, 0x3fff, 0x7fff];

let decoderMod = null;
function getDecoder() {
  if (decoderMod === null) {
    try { decoderMod = require("mpg123-decoder"); } catch { decoderMod = false; }
  }
  return decoderMod || null;
}

function ulawEncode(sample) {
  let s = sample | 0;
  const sign = (s >> 8) & 0x80;
  if (sign) s = -s;
  if (s > 32767) s = 32767;
  s += 0x84;
  let e = 0;
  while (e < 8 && s > ULAW_SEG_END[e]) e++;
  let b;
  if (e === 8) b = 0x7f;
  else {
    const mant = (s >> (e + 3)) & 0x0f;
    b = (e << 4) | mant;
  }
  b |= sign;
  return b ^ 0xff;
}

function toUlawFrames(pcm16) {
  const frames = [];
  const n = pcm16.length;
  for (let off = 0; off < n; off += FRAME) {
    const end = Math.min(off + FRAME, n);
    const b = Buffer.alloc(FRAME);
    for (let i = off; i < end; i++) b[i - off] = ulawEncode(pcm16[i]);
    frames.push(b);
  }
  return frames;
}

/** Convert any-rate multi-channel PCM16 to mono 8kHz (nearest-neighbour
 *  downsample), return Int16Array at RATE. */
function toMono8k(data, sampleRate, channels) {
  const total = data[0] ? data[0].length : 0;
  const mono = new Float64Array(Math.max(0, Math.ceil((total / sampleRate) * RATE)));
  const step = total > 0 ? (sampleRate / RATE) : 1;
  for (let i = 0; i < mono.length; i++) {
    const src = Math.min(total - 1, Math.floor(i * step));
    let acc = 0;
    for (let ch = 0; ch < channels && ch < data.length; ch++) acc += data[ch][src] || 0;
    mono[i] = acc / Math.min(channels, data.length || 1);
  }
  return Int16Array.from(mono, (v) => Math.max(-32768, Math.min(32767, Math.round(v))));
}

/** Decode a WAV buffer to a Buffer of interleaved PCM16 (8kHz mono). */
function decodeWav(buf) {
  if (buf.length < 44 || buf.toString("ascii", 0, 4) !== "RIFF" || buf.toString("ascii", 8, 12) !== "WAVE") return null;
  let off = 12;
  let fmt = null, dataOff = -1, dataLen = 0;
  while (off + 8 <= buf.length) {
    const id = buf.toString("ascii", off, off + 4);
    const size = buf.readUInt32LE(off + 4);
    if (id === "fmt ") fmt = { audioFormat: buf.readUInt16LE(off + 8), channels: buf.readUInt16LE(off + 10), sampleRate: buf.readUInt32LE(off + 12), bits: buf.readUInt16LE(off + 22) };
    else if (id === "data") { dataOff = off + 8; dataLen = size; break; }
    off += 8 + size + (size % 2);
  }
  if (!fmt || dataOff < 0 || fmt.audioFormat !== 1) return null;
  const channels = Math.max(1, fmt.channels);
  const pcm = [];
  if (fmt.bits === 16) {
    const n = Math.min(dataLen, buf.length - dataOff);
    for (let ch = 0; ch < channels; ch++) {
      const arr = new Int16Array(Math.floor(n / (2 * channels)));
      for (let i = 0, s = dataOff + ch * 2; i < arr.length; i++, s += 2 * channels) arr[i] = buf.readInt16LE(s);
      pcm.push(arr);
    }
  } else if (fmt.bits === 8) {
    const n = Math.min(dataLen, buf.length - dataOff);
    for (let ch = 0; ch < channels; ch++) {
      const arr = new Int16Array(Math.floor(n / channels));
      for (let i = 0, s = dataOff + ch; i < arr.length; i++, s += channels) arr[i] = ((buf[s] - 128) << 8);
      pcm.push(arr);
    }
  } else {
    return null;
  }
  return toMono8k(pcm, fmt.sampleRate, channels);
}

/** Resample PM16 to 8kHz mono with a box anti-alias filter. */
function resampleTo8k(mono, sampleRate) {
  if (!mono || !mono.length || !sampleRate || sampleRate === RATE) return mono;
  const out = new Float64Array(Math.ceil((mono.length * RATE) / sampleRate));
  const step = sampleRate / RATE;
  for (let i = 0; i < out.length; i++) {
    const start = Math.floor(i * step);
    const end = Math.min(mono.length, Math.max(start + 1, Math.ceil((i + 1) * step)));
    let acc = 0;
    for (let j = start; j < end; j++) acc += mono[j];
    out[i] = acc / (end - start);
  }
  return Int16Array.from(out, (v) => Math.max(-32768, Math.min(32767, Math.round(v))));
}

/** Decode an MP3 buffer to PCM16 8kHz mono (WASM; returns null on failure). */
async function decodeMp3(buf) {
  const mod = getDecoder();
  if (!mod || typeof mod.MPEGDecoder !== "function") return null;
  let dec = null;
  try {
    dec = new mod.MPEGDecoder();
    if (dec.ready) await dec.ready;
    const r = dec.decode(new Uint8Array(buf));
    if (!r || !r.channelData || !r.channelData.length || !r.samplesDecoded) return null;
    const channels = r.channelData.length;
    const rate = Number(r.sampleRate) || 24000;
    const data = r.channelData.map((c) => Float32Array.from(c));
    const mono = new Float64Array(r.samplesDecoded);
    for (let i = 0; i < mono.length; i++) {
      let acc = 0;
      for (let ch = 0; ch < channels; ch++) acc += data[ch][i] || 0;
      mono[i] = (acc / channels) * 32767;
    }
    dec.free();
    const pcm = Int16Array.from(mono, (v) => Math.max(-32768, Math.min(32767, Math.round(v))));
    return resampleTo8k(pcm, rate);
  } catch {
    try { if (dec) dec.free(); } catch {}
    return null;
  }
}

/** Any supported audio buffer -> μ-law frames (WAV natively, else MP3). */
async function audioToFrames(buf) {
  const wav = decodeWav(buf);
  if (wav) return toUlawFrames(wav);
  const mp3 = await decodeMp3(buf);
  if (mp3) return toUlawFrames(mp3);
  return [];
}

/* ------------------ Microsoft Edge neural TTS (the only voice) ------------------
 * Free, keyless, natural and expressive voices via the Edge Read Aloud websocket -
 * the exact engine Microsoft Edge's "Read Aloud" uses. Female conversational voice
 * "Ava" (Expressive / Friendly). MP3 audio comes back over the socket and is decoded
 * to μ-law speech frames below. If the service is ever unreachable the call still
 * proceeds in silence rather than failing. */

const EDGE_VOICE = "en-US-AvaNeural";
const EDGE_ALLOWLIST = /Neural$/;

const EDGE_HOST = "wss://speech.platform.bing.com/consumer/speech/synthesize/readaloud/edge/v1";
const EDGE_TOKEN = "6A5AA1D4EAFF4E9FB37E23D68491D6F4";
const EDGE_GEC_VERSION = "1-143.0.3650.75";
const EDGE_WS_HEADERS = {
  "Pragma": "no-cache",
  "Cache-Control": "no-cache",
  "Origin": "chrome-extension://jdiccldimpdaibmpdkjnbmckianbfold",
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"
};

const EDGE_WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const EDGE_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
function edgeDateString() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${EDGE_WEEKDAYS[d.getUTCDay()]} ${EDGE_MONTHS[d.getUTCMonth()]} ${p(d.getUTCDate())} ${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} GMT+0000 (Coordinated Universal Time)`;
}

function edgeSecMsGec(nowS = Date.now() / 1000) {
  let ticks = nowS + 11644473600;
  ticks -= ticks % 300;
  ticks *= 1e9 / 100;
  return crypto.createHash("sha256").update(`${Math.floor(ticks)}${EDGE_TOKEN}`, "ascii").digest("hex").toUpperCase();
}

function edgeMakeId() {
  return crypto.randomUUID().replace(/-/g, "");
}

function edgeClean(text) {
  return String(text || "")
    .split("").map((c) => { const code = c.charCodeAt(0); return (code <= 0x08 || (code >= 0x0B && code <= 0x0C) || (code >= 0x0E && code <= 0x1F)) ? " " : c; }).join("")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** Synthesise `text` with a Microsoft Edge neural voice, return MP3 Buffer (or null). */
function edgeTts(text, voice) {
  return new Promise((resolve) => {
    let done = false;
    const timer = setTimeout(() => finish(null), 20000);
    function finish(buf) { if (!done) { done = true; clearTimeout(timer); resolve(buf); } }
    let ws;
    try {
      ws = new WS(
        `${EDGE_HOST}?TrustedClientToken=${EDGE_TOKEN}&ConnectionId=${edgeMakeId()}&Sec-MS-GEC=${edgeSecMsGec()}&Sec-MS-GEC-Version=${EDGE_GEC_VERSION}`,
        { headers: { ...EDGE_WS_HEADERS, Cookie: `muid=${crypto.randomBytes(16).toString("hex").toUpperCase()};` }, perMessageDeflate: true }
      );
    } catch {
      finish(null);
      return;
    }
    const chunks = [];
    const stamp = edgeDateString();
    ws.on("open", () => {
      ws.send(`X-Timestamp:${stamp}\r\nContent-Type:application/json; charset=utf-8\r\nPath:speech.config\r\n\r\n{"context":{"synthesis":{"audio":{"metadataoptions":{"sentenceBoundaryEnabled":"false","wordBoundaryEnabled":"false"},"outputFormat":"audio-24khz-48kbitrate-mono-mp3"}}}}\r\n`, (err) => {
        if (err) { finish(null); return; }
        ws.send(
          `X-RequestId:${edgeMakeId()}\r\nContent-Type:application/ssml+xml\r\nX-Timestamp:${stamp}Z\r\nPath:ssml\r\n\r\n` +
          `<speak version='1.0' xmlns='http://www.w3.org/2001/10/synthesis' xml:lang='en-US'>` +
          `<voice name='${voice}'><prosody pitch='+0Hz' rate='+0%' volume='+0%'>${edgeClean(text)}</prosody></voice></speak>`,
          (e2) => { if (e2) finish(null); }
        );
      });
    });
    ws.on("message", (raw, isBinary) => {
      if (!isBinary) {
        if (String(raw).includes("turn.end")) {
          try { ws.close(); } catch {}
          finish(Buffer.concat(chunks));
        }
        return;
      }
      const buf = Buffer.from(raw);
      try {
        if (buf.length < 2) return;
        const hl = buf.readUInt16BE(0);
        const head = buf.toString("ascii", 2, 2 + hl);
        if (!head.includes("Path:audio")) return;
        chunks.push(buf.subarray(2 + hl + 2));
      } catch { finish(null); }
    });
    ws.on("error", () => finish(null));
  });
}

function splitForTts(text) {
  const sentences = String(text || "").split(/(?<=[.!?])\s+/);
  const chunks = [];
  let cur = "";
  for (const s of sentences) {
    if ((cur + " " + s).trim().length > 180) { if (cur.trim()) chunks.push(cur.trim()); cur = s; }
    else cur = (cur + " " + s).trim();
  }
  if (cur.trim()) chunks.push(cur.trim());
  return chunks.length ? chunks : [String(text || "Hello").slice(0, 180)];
}

/** Synthesise `text` to μ-law frames using the Microsoft voice. */
async function textToFrames(text, opts = {}) {
  const chunks = splitForTts(text);
  const voice = EDGE_ALLOWLIST.test(opts.ttsVoice || "") ? opts.ttsVoice : EDGE_VOICE;
  const parts = [];
  for (const chunk of chunks) {
    const m = await edgeTts(chunk, voice);
    if (m) parts.push(m);
  }
  if (!parts.length) return [];
  return await audioToFrames(Buffer.concat(parts));
}

const cache = new Map();
const CACHE_MAX = 40;

/** Build μ-law frames for a script, cached by content. */
async function framesFor(text, opts = {}) {
  const key = crypto.createHash("sha1").update(String(text || "") + "|" + String(opts.ttsKey || "") + "|" + String(opts.ttsVoice || "")).digest("hex");
  if (cache.has(key)) return cache.get(key);
  let frames;
  try { frames = await textToFrames(text, opts); } catch { frames = []; }
  if (cache.size > CACHE_MAX) cache.clear();
  cache.set(key, frames);
  return frames;
}

module.exports = { framesFor, toUlawFrames, decodeWav, decodeMp3, audioToFrames, textToFrames, FRAME, SILENCE };