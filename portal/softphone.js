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
    const result = { ok: false, outcome: "failed", last: "", steps, media: null, extra: null };

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
        // Real speech detector. The μ-law energy of an actual voice syllable is
        // far higher than line hiss/comfort noise; require a sustained loud
        // streak (several 20ms packets) before believing the person spoke, so
        // the call never "starts on its own" because of noise.
        const SPEECH_THRESH = 400;  // mean squared sample distance (0xFF=silence)
        const SPEECH_WINDOW = 12;   // packets to look back over
        const SPEECH_MIN = 6;       // of the last 12 packets must be loud
        const makeSpeechGate = () => {
          const hist = [];
          return (e) => {
            hist.push(e > SPEECH_THRESH ? 1 : 0);
            if (hist.length > SPEECH_WINDOW) hist.shift();
            let loud = 0;
            for (const v of hist) loud += v;
            return loud >= SPEECH_MIN;
          };
        };

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

        // Listen for the far side's reply: wait until they say something that
        // then goes quiet for a beat (or a hard timeout, so a silent answering
        // machine still lets the script continue).
        const listenForReply = (holdMs) =>
          new Promise((resolve) => {
            let sawSpeech = false;
            let lastSpeechAt = 0;
            let done = false;
            const gate = makeSpeechGate();
            const finish = (v) => { if (done) return; done = true; try { callSession.off("audioPacket", onAudio); } catch {} clearTimeout(hard); resolve(v); };
            const hard = setTimeout(() => finish("timeout"), Math.max(2000, holdMs));
            const onAudio = (pkt) => {
              const e = pktEnergy(pkt);
              if (gate(e)) {
                if (!sawSpeech) { sawSpeech = true; steps.push("heard:reply-speech"); }
                lastSpeechAt = Date.now();
                return;
              }
              if (sawSpeech && lastSpeechAt && Date.now() - lastSpeechAt > 1200) finish("quiet");
            };
            callSession.on("audioPacket", onAudio);
            callSession.once("disposed", () => finish("disposed"));
          });

        // ---- Wait for the FAR SIDE TO SPEAK before we say a word ----
        // The call starts ONLY after the other person says something (their
        // greeting), never on its own, never on a timer. Listening to their
        // first words also gives us a chance to infer which language they are
        // speaking. If the far side never speaks we simply keep the line open
        // and wait - the call must not talk over a silent listener.
        const heardSpeech = await new Promise((resolveHeard) => {
          let done = false;
          const gate = makeSpeechGate();
          const finishHeard = (v) => { if (done) return; done = true; try { callSession.off("audioPacket", onAudio); } catch {} resolveHeard(v); };
          const onAudio = (pkt) => {
            const e = pktEnergy(pkt);
            if (gate(e)) {
              steps.push("heard:far-side-spoken:e" + Math.round(e));
              finishHeard(true);
            }
          };
          callSession.on("audioPacket", onAudio);
          callSession.once("disposed", () => finishHeard(false));
        });
        if (!heardSpeech) {
          // The other side answered but never spoke. We do not talk over a
          // silent listener and we do not hang up on ourselves - just hold the
          // line until they hang up or finally say something.
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
        }

        // ---- Speak the script, pausing only after questions ----
        // Natural sales cadence: statements flow; when a line ends in a
        // question, give the person the floor and wait for their answer (VAD),
        // then continue. Never plows through the whole script in one go.
        // A ~1 s lead of silence (50 frames) lets the SBC lock onto our media
        // flow AFTER the far side has spoken so the first words never drop.
        if (segs.length) {
          await speak(Buffer.alloc(50 * 160, 0xff));
          for (let i = 0; i < segs.length; i++) {
            if (callSession.disposed || settled) break;
            steps.push("say:" + (i + 1) + "/" + segs.length);
            await speak(Buffer.concat(segs[i].frames));
            steps.push("said:" + (i + 1));
            const isQ = /\?$/.test(segs[i].text.trim()) && i < segs.length - 1;
            if (isQ) {
              keepAliveSilence();
              const turn = await listenForReply(9000);
              steps.push("turn:" + (i + 1) + ":" + turn);
              if (turn === "disposed") break;
              if (turn === "quiet") keepAliveSilence(); // resume streaming silence
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