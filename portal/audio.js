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

const RATE = 8000;
const FRAME = 160;
const SILENCE = Buffer.alloc(FRAME, 0x7f);

let decoderMod = null;
function getDecoder() {
  if (decoderMod === null) {
    try { decoderMod = require("mpg123-decoder"); } catch { decoderMod = false; }
  }
  return decoderMod || null;
}

function ulawEncode(sample) {
  let s = sample | 0;
  const sign = s < 0 ? 0x80 : 0;
  if (s < 0) s = -s;
  if (s > 32635) s = 32635;
  s += 132;
  let exp = 1;
  while (s >>= 1) exp++;
  let mant = (s >> (exp === 8 ? 6 : exp === 7 ? 5 : exp)) & 0x0f;
  return sign | ((exp - 1) << 4) | mant;
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
    const data = r.channelData.map((c) => Float32Array.from(c));
    const mono = new Float64Array(r.samplesDecoded);
    for (let i = 0; i < mono.length; i++) {
      let acc = 0;
      for (let ch = 0; ch < channels; ch++) acc += data[ch][i] || 0;
      mono[i] = (acc / channels) * 32767;
    }
    dec.free();
    return Int16Array.from(mono, (v) => Math.max(-32768, Math.min(32767, Math.round(v))));
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

/* ------------------------- no-key TTS providers ------------------------- */

const TTS_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36";

async function fetchBuf(url, headers = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 15000);
  try {
    const res = await fetch(url, { headers: { "User-Agent": TTS_UA, ...headers }, signal: ctrl.signal });
    if (!res.ok) return null;
    const b = Buffer.from(await res.arrayBuffer());
    return b && b.length ? b : null;
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
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

async function googleTts(chunk) {
  return await fetchBuf(
    "https://translate.google.com/translate_tts?ie=UTF-8&client=tw-ob&tl=en-US&total=1&idx=0&q=" + encodeURIComponent(chunk)
  );
}

async function streamElementsTts(chunk, voice = "Brian") {
  return await fetchBuf(
    "https://api.streamelements.com/kappa/v2/speech?voice=" + encodeURIComponent(voice) + "&text=" + encodeURIComponent(chunk)
  );
}

/** Synthesise `text` to μ-law frames. Tries providers in order; premium key
 *  (ttsKey) is used when present. Returns [] if every provider is unreachable
 *  (caller still proceeds - the agent path carries the script). */
async function textToFrames(text, opts = {}) {
  const chunks = splitForTts(text);
  const parts = [];
  for (const chunk of chunks) {
    const m = await fetchBuf("https://api.voicerss.org/tts?key=" + encodeURIComponent(opts.ttsKey) + "&hl=en-us&v=Brian&c=MP3&f=8khz_8bit_mono&src=" + encodeURIComponent(chunk));
    if (m) { parts.push(m); continue; }
    const g = await googleTts(chunk);
    if (g) { parts.push(g); continue; }
    const s = await streamElementsTts(chunk, opts.ttsVoice || "Brian");
    if (s) parts.push(s);
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