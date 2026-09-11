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

        if (frames.length) {
          const audio = Buffer.concat(frames);
          // Pad with mu-law silence (0xFF) up to the requested hold time so the
          // SBC keeps receiving continuous RTP until we send BYE.
          const want = Math.floor((durationMs / 20) * 160);
          const padded = audio.length >= want ? audio : Buffer.concat([audio, Buffer.alloc(want - audio.length, 0xff)]);
          streamer = callSession.streamAudio(padded);
          streamer.once("finished", () => steps.push("audio:finished"));
        }

        holdTimer = setTimeout(() => finish(), durationMs);
        watchdog = setTimeout(() => fail("watchdog timeout"), durationMs + 60000);
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