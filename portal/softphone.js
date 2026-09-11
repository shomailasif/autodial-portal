/* RingCentral soft-phone driver backed by RingCentral's official Softphone
 * SDK (@ringcentral/ringcentral-softphone-ts -> "ringcentral-softphone").
 *
 * Replaces the previous hand-written REGISTER/INVITE/SRTP engine with the
 * code RingCentral ships and validates against its own SBCs:
 *   - TLS registration + digest auth (executed by the SDK)
 *   - SDP offer/answer with SDES crypto is built by the SDK
 *   - SRTP (AES_CM_128_HMAC_SHA1_80) is handled by werift-rtp
 *   - a UDP "hello" punch-through is sent on answer so the SBC learns the
 *     real media source IP:port (the container sits behind NAT)
 *   - media frames are paced at exactly 20ms by the SDK's Streamer
 *
 * The portal feeds this driver already-encoded G.711/PCMU 8 kHz frames
 * (160 bytes per 20ms packet), produced by audio.js. Codec = PCMU/8000,
 * whose encoder/decoder in the SDK are pass-through.
 */
const Softphone = require("ringcentral-softphone");
const stt = require("./stt");     // free keyless Whisper language detection (lazy + hard timeouts)
const audio = require("./audio"); // Edge neural TTS, used to re-voice the script to a detected language

/* ------------------------------------------------------------------ helpers */

/** G.711 mu-law bytes for a 440 Hz tone, one 20 ms frame at 8 kHz. */
function pcmuTone(frame = 160) {
  const out = Buffer.alloc(frame);
  const A = 4000;
  for (let i = 0; i < frame; i++) {
    const v = Math.sin((2 * Math.PI * 440 * i) / 8000) * A;
    out[i] = ((v | 0) ^ 0xff) & 0xff;
  }
  return out;
}

function toFrames(payloads) {
  return (Array.isArray(payloads) ? payloads : [])
    .map((f) => (Buffer.isBuffer(f) ? f : Buffer.from(f)))
    .filter((f) => f.length);
}

/** Convert captured μ-law frames into an 8 kHz mono PCM16 WAV (STT input).
 *  Returns null when there is too little audio to be meaningful. */
function ulawFramesToWav(frames) {
  if (!Array.isArray(frames) || !frames.length) return null;
  const n = frames.reduce((a, f) => a + (f && f.length ? f.length : 0), 0);
  if (n < 1600) return null; // < 200 ms of speech is nothing
  const pcm = Buffer.allocUnsafe(n * 2);
  let off = 0;
  for (const f of frames) {
    if (!f) continue;
    for (let i = 0; i < f.length; i++) { pcm.writeInt16LE(stt.ulawToLinear(f[i]), off); off += 2; }
  }
  const h = Buffer.alloc(44);
  h.write("RIFF", 0, "ascii"); h.writeUInt32LE(36 + pcm.length, 4); h.write("WAVE", 8, "ascii");
  h.write("fmt ", 12, "ascii"); h.writeUInt32LE(16, 16); h.writeUInt16LE(1, 20); h.writeUInt16LE(1, 22);
  h.writeUInt32LE(8000, 24); h.writeUInt32LE(16000, 28); h.writeUInt16LE(2, 32); h.writeUInt16LE(16, 34);
  h.write("data", 36, "ascii"); h.writeUInt32LE(pcm.length, 40);
  return Buffer.concat([h, pcm]);
}

/** Build the SDK options from the same shape trunk.js passes today. */
function sdkOptions(o) {
  const user = String(o.user || "");
  const pass = String(o.pass || "");
  const authId = String(o.authId || user);
  const domain = String(o.domain || "sip.ringcentral.com").replace(/:\d+$/, "");
  const proxy = String(o.proxy || "sip40.ringcentral.com").replace(/:\d+$/, "");
  const port = Number(o.port || 5096);
  return {
    domain,
    outboundProxy: `${proxy}:${port}`,
    username: user,
    password: pass,
    authorizationId: authId,
    codec: "PCMU/8000",
    ...(o.debug ? { ignoreTlsCertErrors: true } : {}),
  };
}

/* ------------------------------------------------------------------ calls */

/**
 * Place one outbound PCMU call through RingCentral using the official SDK.
 *
 * opts: { user, pass, authId, domain, proxy, port, number,
 *         durationMs?, payloads?, debug? }
 *
 * Resolves with the same shape the trunk layer expects:
 *   { ok, outcome, last, steps, media: {remoteIp, remotePort, remoteKey,
 *     inboundUnlocked}, extra }
 */
function sipCallOnce(o) {
  return new Promise((resolve) => {
    const number = String(o.number || o.callee || "").replace(/[^\d+]/, "");
    const durationMs = Math.max(2000, Number(o.durationMs || 20000));
    const frames = toFrames(o.payloads);
    const steps = [];
    const result = { ok: false, outcome: "failed", last: "", steps, media: null, stt: null, extra: null };

    let softphone = null;
    let callSession = null;
    let streamer = null;
    let holdTimer = null;
    let watchdog = null;
    let settled = false;

    const cleanup = () => {
      try { if (streamer) streamer.stop(); } catch {}
      try { if (callSession && !callSession.disposed) callSession.hangup(); } catch {}
      setTimeout(() => { try { if (softphone) softphone.revoke(); } catch {} }, 250);
    };

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(holdTimer);
      clearTimeout(watchdog);
      result.steps = steps;
      resolve(result);
      cleanup();
    };

    const fail = (message, outcome) => {
      result.last = message;
      if (outcome) result.outcome = outcome;
      finish();
    };

    (async () => {
      try {
        softphone = new Softphone(sdkOptions(o));
        // The SDK's TLS socket is created in the constructor; a failed
        // connect/read surfaces as an unhandled 'error' event which would
        // crash the whole portal process. Guard it here.
        if (softphone.client) {
          softphone.client.on("error", (e) => {
            steps.push("tls-error:" + (e && e.message));
            if (!result.ok && result.last === "failed") fail((e && e.message) || "TLS error", "error");
          });
        }
        steps.push("connect:" + softphone.sipInfo.outboundProxy);
        softphone.on("outboundMessage", (m) => {
          const first = String(m).trim().split("\r\n")[0];
          if (steps.length < 40) steps.push("> " + first);
        });
        softphone.on("message", (m) => {
          const first = String(m).trim().split("\r\n")[0];
          if (steps.length < 60) steps.push("< " + first);
        });

        await softphone.register();
        steps.push("registered:" + softphone.sipInfo.username + "@" + softphone.sipInfo.domain);

        callSession = await softphone.call(number);
        steps.push("invite:" + number);

        // The SDK emits "busy" on 486 and "disposed" on termination.
        callSession.once("busy", () => fail("SIP/2.0 486 Busy Here", "busy"));
        callSession.once("disposed", () => {
          if (!result.ok && result.last === "failed") fail("call disposed before answer", "no-answer");
        });

        await new Promise((res, rej) => {
          const to = setTimeout(() => rej(new Error("answer timeout")), 60000);
          callSession.once("answered", () => { clearTimeout(to); res(); });
          callSession.once("disposed", () => { clearTimeout(to); rej(new Error("call disposed before answer")); });
          callSession.once("busy", () => { clearTimeout(to); rej(new Error("busy")); });
        });

        steps.push("answered:" + callSession.sessionId);
        result.ok = true;
        result.outcome = "answered";
        result.media = {
          remoteIp: callSession.remoteIP,
          remotePort: callSession.remotePort,
          remoteKey: !!callSession.srtpSession,
          inboundUnlocked: true,
        };
        result.last = "SIP/2.0 200 OK";

        // ---- Speech units ----
        // Per-unit μ-law segments (each decoded independently so there are no
        // MP3 concat breaks inside the stream). If the trunk only handed us a
        // flat payload, treat it as a single unit.
        const segs = (Array.isArray(o.segments) && o.segments.length)
          ? o.segments
              .map((s) => ({ text: (s && s.text) || "", frames: (s && Array.isArray(s.frames)) ? s.frames : (Array.isArray(s) ? s : toFrames([s])) }))
              .filter((s) => s.frames.length)
          : (frames.length ? [{ text: o.script || "", frames }] : []);

        const pktEnergy = (pkt) => {
          let e = 0;
          const p = pkt.payload;
          for (let i = 0; i < p.length; i++) { const d = p[i] ^ 0xff; e += d * d; }
          return e / Math.max(1, p.length);
        };
        // Voice detector (adaptive, not a magic number).
        //   - It keeps a running noise floor = 10th percentile of the last
        //     ~3s of packet energy. Line hiss / comfort noise / room ambient
        //     become the floor, so a fixed threshold can never be beaten by a
        //     noisy line - only real speech is much louder than the floor.
        //   - A packet is "loud" when energy >= max(floor * VOICE_RATIO, ABS_MIN).
        //   - The person must talk CONTINUOUSLY for VOICE_ONSET packets (a
        //     click / cough / DTMF blip is too short to open the gate).
        //   - The utterance only "ends" after a quiet run of VOICE_QUIET
        //     packets (they finished talking). The call then proceeds - it
        //     never starts in the middle of someone's sentence. If they never
        //     talk, the detector simply never opens and the call stays silent.
        const VOICE_ABS_MIN = 1000; // mean-squared μ-law level; nothing below counts
        const VOICE_RATIO = 5;      // loud = >= 5x the line's noise floor
        const VOICE_ONSET = 10;     // ~200ms of continuous loud to believe onset
        const VOICE_QUIET = 40;     // ~800ms of quiet = their utterance ended
        const VOICE_MAXTALK = 600;  // if they talk 12s non-stop, end anyway
        const FLOOR_WIN = 160;      // packets considered for noise floor (~3.2s)
        function createVoiceDetector() {
          const seen = [];
          let loudRun = 0;
          let quietRun = 0;
          let talking = false;
          let talkTime = 0;
          const floorAt = () => {
            if (seen.length < 24) return Math.max(200, VOICE_ABS_MIN);
            const s = seen.slice(0, seen.length).sort((a, b) => a - b);
            return Math.max(120, s[Math.min(s.length - 1, Math.floor(s.length * 0.1))]);
          };
          return {
            feed(e) {
              seen.push(e);
              if (seen.length > FLOOR_WIN) seen.shift();
              const f = floorAt();
              const loud = e >= Math.max(f * VOICE_RATIO, VOICE_ABS_MIN);
              if (!talking) {
                loudRun = loud ? loudRun + 1 : 0;
                if (loudRun >= VOICE_ONSET) { talking = true; quietRun = 0; talkTime = 0; return "onset"; }
                return "idle";
              }
              talkTime++;
              quietRun = loud ? 0 : quietRun + 1;
              if (quietRun >= VOICE_QUIET) { talking = false; return "done"; }
              if (talkTime >= VOICE_MAXTALK) { talking = false; return "done"; }
              return "talking";
            },
          };
        }
        // Wait for the far side to produce ONE complete utterance. Resolves
        // { state: "answered", frames } when they talked and fell quiet (never
        // in the middle of their speech), or { state: "disposed" } if they hang
        // up. If they never talk we wait as long as it takes - silence is
        // streamed separately so the call never advances or hangs up while the
        // listener is quiet. When capture is set, the μ-law frames from voice
        // onset until they stopped are kept (the caller feeds them to STT).
        const waitForUtterance = (label, opts = {}) =>
          new Promise((resolve) => {
            const det = createVoiceDetector();
            const utt = [];
            let collecting = false;
            let done = false;
            const finish = (v) => { if (done) return; done = true; try { callSession.off("audioPacket", onAudio); } catch {} resolve({ state: v, frames: opts.capture ? utt.slice() : [] }); };
            const onAudio = (pkt) => {
              const e = pktEnergy(pkt);
              const ev = det.feed(e);
              if (ev === "onset") { steps.push("heard:" + label + ":voice:e" + Math.round(e)); collecting = true; }
              if (ev === "done") { collecting = false; return finish("answered"); }
              if (collecting && pkt && pkt.payload && pkt.payload.length) utt.push(Buffer.from(pkt.payload));
            };
            callSession.on("audioPacket", onAudio);
            callSession.once("disposed", () => finish("disposed"));
          });

        let silenceStreamer = null;
        let speaking = false;
        const stopCurrent = () => { try { if (silenceStreamer) silenceStreamer.stop(); } catch {} silenceStreamer = null; };
        const keepAliveSilence = () => {
          if (callSession.disposed || settled || speaking) return;
          stopCurrent();
          silenceStreamer = callSession.streamAudio(Buffer.alloc(300 * 160, 0xff)); // 6 s of silence
          silenceStreamer.once("finished", () => { if (!callSession.disposed && !settled && !speaking) keepAliveSilence(); });
        };

        const speak = (buf) =>
          new Promise((res) => {
            stopCurrent();
            speaking = true;
            const s = callSession.streamAudio(buf);
            s.once("finished", () => { speaking = false; res(); });
          });

        // ---- Converge on the far side's voice before saying a word ----
        // The call starts ONLY after the other person has SPOKEN AND FINISHED
        // their first utterance (greeting). Never on its own, never on a timer.
        // If the far side never speaks we keep the line open and hold - we do
        // not talk over a silent listener and we do not hang up on ourselves.
        // The captured utterance is handed to language detection so the voice
        // and script match what the listener actually speaks.
        const first = await waitForUtterance("start", { capture: true });
        if (first.state !== "answered") {
          steps.push("far-side-never-spoke");
          keepAliveSilence();
          const holdMs = Math.max(10000, durationMs + 120000);
          watchdog = setTimeout(() => fail("watchdog timeout", "completed"), holdMs);
          callSession.once("disposed", () => {
            if (!result.ok) return;
            steps.push("far-side-disposed");
            finish();
          });
        } else {
          steps.push("gate:passed");
          // ---- Hear their language before we say a word ----
          // The captured greeting is fed to the in-process Whisper model. The
          // matching neural voice takes over (LANG_VOICES); if STT cannot load
          // or times out (first-run download, 256Mi container, no dependency)
          // we keep the configured voice and the already-rendered script - STT
          // must never stall or break a live call.
          let det = null;
          {
            const wav = ulawFramesToWav(first.frames);
            det = wav ? await stt.detectLanguage(wav, { timeoutMs: 25000 }) : null;
          }
          let chosenVoice = String(o.ttsVoice || "");
          if (det && det.lang) {
            const lang = String(det.lang);
            chosenVoice = stt.LANG_VOICES[lang] || chosenVoice;
            const heard = String(det.text || "").slice(0, 80);
            steps.push("stt:lang=" + lang + (chosenVoice ? ":voice=" + chosenVoice : "") + (heard ? ":hear=" + heard : ""));
            result.stt = { lang, text: String(det.text || "").slice(0, 200) || null, voice: chosenVoice || null, sourceVoice: o.ttsVoice || null, frames: first.frames.length };
          } else {
            steps.push("stt:unavailable:keep=" + (chosenVoice || "default"));
            result.stt = { lang: null, text: null, voice: chosenVoice || null, sourceVoice: o.ttsVoice || null, frames: first.frames.length };
          }
          // Re-voice the script into the detected language when it differs from
          // the voice the segments were rendered with. Bounded hard: if Edge
          // TTS is unreachable or too slow, the pre-rendered speech stays.
          if (chosenVoice && o.ttsVoice && chosenVoice !== o.ttsVoice && segs.length && String(o.script || "").trim()) {
            const re = await Promise.race([
              audio.segmentsFor(String(o.script), { ttsVoice: chosenVoice, ttsKey: o.ttsKey })
                .then((s) => (s && s.length ? s : null))
                .catch(() => null),
              new Promise((res) => setTimeout(() => res(null), 20000)),
            ]);
            if (re) { segs.splice(0, segs.length, ...re); steps.push("voiced:" + chosenVoice + ":units=" + re.length); }
            else steps.push("voiced:fallback:" + chosenVoice);
          }
        }

        // ---- Speak the script, pausing ONLY after questions ----
        // Natural sales cadence: statements flow; after a question the person
        // gets the floor and we WAIT for their answer (no timeout - a quiet
        // listener never forces us to plow ahead). We only continue once they
        // have spoken and finished. A ~1 s lead of silence (50 frames) lets
        // the SBC lock onto our media AFTER the far side has spoken so the
        // first words never drop.
        if (segs.length && !callSession.disposed && !settled) {
          await speak(Buffer.alloc(50 * 160, 0xff));
          for (let i = 0; i < segs.length; i++) {
            if (callSession.disposed || settled) break;
            steps.push("say:" + (i + 1) + "/" + segs.length);
            await speak(Buffer.concat(segs[i].frames));
            steps.push("said:" + (i + 1));
            const isQ = /\?$/.test(segs[i].text.trim()) && i < segs.length - 1;
            if (isQ) {
              keepAliveSilence(); // keep the media flow alive while listening
              const turn = await waitForUtterance("turn" + (i + 1));
              steps.push("turn:" + (i + 1) + ":" + turn.state);
              if (turn.state === "disposed") break;
              await speak(Buffer.alloc(15 * 160, 0xff)); // brief beat of silence after their answer
            }
          }
        } else {
          steps.push("audio:none");
        }

        // ---- Hold the call open ----
        // Keep a continuous stream of silence so the SBC never tears the call
        // down for lack of media. The call ends when the far side hangs up
        // (disposed) or a generous watchdog fires. We never BYE on a fixed
        // speakSeconds timer - that's what made calls "drop on their own".
        if (callSession.disposed || settled) {
          if (callSession.disposed) steps.push("far-side-disposed");
          finish();
        } else {
          const holdMs = Math.max(10000, durationMs + 120000);
          keepAliveSilence();
          watchdog = setTimeout(() => fail("watchdog timeout", "completed"), holdMs);
          callSession.once("disposed", () => {
            if (!result.ok) return;
            steps.push("far-side-disposed");
            finish();
          });
        }
      } catch (e) {
        const msg = (e && e.message) || String(e);
        result.outcome = msg.toLowerCase().includes("busy") ? "busy" : "error";
        fail(msg);
      }
    })();
  });
}

/* ----------------------------------------------------------------- diag */

/** Register the SIP device once (diagnostic / sign-of-life), no call. */
async function registerSession(o) {
  const steps = [];
  let softphone = null;
  try {
    softphone = new Softphone(sdkOptions(o));
    if (softphone.client) {
      softphone.client.on("error", (e) => steps.push("tls-error:" + (e && e.message)));
    }
    if (o.debug) softphone.enableDebugMode();
    await softphone.register();
    steps.push("registered:" + softphone.sipInfo.username + "@" + softphone.sipInfo.domain + " via " + softphone.sipInfo.outboundProxy);
    return { ok: true, steps, last: "SIP/2.0 200 OK", host: softphone.sipInfo.outboundProxy };
  } catch (e) {
    const msg = (e && e.message) || String(e);
    steps.push(msg);
    return { ok: false, steps, last: msg };
  } finally {
    setTimeout(() => { try { if (softphone) softphone.revoke(); } catch {} }, 250);
  }
}

async function rawReg(o) {
  const r = await registerSession(o);
  return { ok: r.ok, steps: r.steps, last: r.last };
}

module.exports = { sipCallOnce, pcmuTone, rawReg, registerSession };