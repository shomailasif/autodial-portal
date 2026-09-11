/*
 * stt.js - free, keyless speech-to-text + language detection.
 *
 * Runs a tiny Whisper model (whisper-tiny) INSIDE the portal process via
 * @huggingface/transformers (onnxruntime WASM/native, no external API, no
 * key, no money). Used to determine which language the far side of a call is
 * speaking so the call can reply in that language.
 *
 * The dependency is loaded lazily and every entry is wrapped in a hard
 * timeout: if the model cannot load (first-run download, platform limits) the
 * caller just gets null and the call proceeds in the configured default
 * language - speech understanding must never break a live call.
 */
const crypto = require("node:crypto");

// Voice used per detected language: Microsoft Edge neural voices (the same
// free engine that synthesises the script). Safe to speak the sales script in.
const LANG_VOICES = {
  en: "en-US-AvaNeural",
  es: "es-MX-DaliaNeural",
  fr: "fr-FR-DeniseNeural",
  de: "de-DE-KatjaNeural",
  pt: "pt-BR-FranciscaNeural",
  hi: "hi-IN-SwaraNeural",
  it: "it-IT-IsabellaNeural",
  ur: "ur-PK-UzmaNeural",
  ar: "ar-SA-ZariyahNeural",
  tr: "tr-TR-EmelNeural",
  nl: "nl-NL-ColetteNeural",
  pl: "pl-PL-ZofiaNeural",
  ru: "ru-RU-SvetlanaNeural",
  uk: "uk-UA-PolinaNeural",
  ja: "ja-JP-NanamiNeural",
  ko: "ko-KR-SunHiNeural",
  zh: "zh-CN-XiaoxiaoNeural",
  id: "id-ID-GadisNeural",
  vi: "vi-VN-HoaiMyNeural",
  th: "th-TH-PremwadeeNeural",
  ms: "ms-MY-YasminNeural",
  sw: "sw-KE-ZuriNeural",
};

/** Convert a μ-law byte to a signed 16-bit linear sample (RFC 3551). */
function ulawToLinear(u) {
  const t = ~u;
  let sign = (t & 0x80) ? -1 : 1;
  let exponent = (t >> 4) & 0x07;
  let mantissa = t & 0x0f;
  let sample = ((mantissa << 3) + 0x84) << exponent;
  return sign * (sample - 0x84);
}

let pipelinePromise = null;

/** Lazy-load the (big) model once and cache the pipeline. Returns null if the
 *  backend/model cannot load on this host. */
function getRecognizer() {
  if (pipelinePromise) return pipelinePromise;
  pipelinePromise = (async () => {
    const tf = require("@huggingface/transformers"); // may throw -> fallback
    const model = process.env.STT_MODEL || "onnx-community/whisper-tiny";
    const stt = await tf.pipeline("automatic-speech-recognition", model);
    return stt;
  })().catch(() => null);
  return pipelinePromise;
}

/**
 * Detect the language + text of a PCM16 mono WAV buffer.
 *
 * wav: Buffer (RIFF/WAVE, PCM 16-bit, any sample rate, mono/stereo ok).
 * Returns { lang, text } or null on any failure (timeout, no model, decode).
 * `lang` is a 2-letter code from LANG_VOICES if recognised else "en".
 */
async function detectLanguage(wav, { timeoutMs = 35000 } = {}) {
  if (!wav || wav.length < 44) return null;
  try {
    const stt = await Promise.race([
      getRecognizer(),
      new Promise((res) => setTimeout(() => res(null), timeoutMs)),
    ]);
    if (!stt) return null;

    const rate = wav.readUInt32LE(24) || 16000;
    const ch = wav.readUInt16LE(22) || 1;
    const n = Math.floor((wav.length - 44) / 2 / ch);
    if (n < 1600) return null; // <100ms of audio is nothing
    const audio = new Float32Array(n);
    for (let i = 0; i < n; i++) {
      const s = wav.readInt16LE(44 + i * 2 * ch);
      audio[i] = s / 32768;
    }
    const out = await Promise.race([
      stt(audio, { language: "auto" }),
      new Promise((res) => setTimeout(() => res(null), timeoutMs)),
    ]);
    if (!out || !out.text) return null;
    const text = String(out.text).trim();
    const lang = String((out.language) ? out.language : guessLang(text));
    return { lang, text };
  } catch {
    return null;
  }
}

/** Cheap fallback when whisper does not report language: classify by script. */
function guessLang(text) {
  const t = String(text || "");
  if (/[¡¿áéíóúüñ]/.test(t) && /[a-záéíóúüñ]/i.test(t)) return "es";
  if (/[àâæçéèêëîïôœùûüÿ]+/i.test(t)) return "fr";
  if (/[ßäöü]/.test(t)) return "de";
  if (/[\u0900-\u097F]/.test(t)) return "hi";
  if (/[\u0600-\u06FF]/.test(t)) return "ar";
  if (/[\u0400-\u04FF]/.test(t)) return "ru";
  if (/[\u4E00-\u9FFF]/.test(t)) return "zh";
  if (/[\u3040-\u30FF]/.test(t)) return "ja";
  if (/[\uAC00-\uD7AF]/.test(t)) return "ko";
  return "en";
}

module.exports = { detectLanguage, guessLang, LANG_VOICES, ulawToLinear };