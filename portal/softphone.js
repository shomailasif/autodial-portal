/* RingCentral soft-phone driver (dependency-free Node).
 *
 * Proven recipe (verified live against sip40.ringcentral.com:5096):
 *  - REGISTER  : Request-URI = sip:<user>@<domain>, Contact = proxy-based,
 *                digest user = authorizationId, HA1 realm = <domain>,
 *                digest uri = "sip:<domain>".
 *  - INVITE    : Via/Contact carry the TLS socket local address:port,
 *                Route uses "<proxy>:<port>;transport=tls;lr",
 *                digest carried in Proxy-Authorization (not Authorization),
 *                SDP body starts directly after the header separator (no
 *                extra blank line - that caused "400 Bad SDP").
 *  - The media/crypto answer comes in 183 Session Progress; after 200 OK
 *    we ACK and stream G.711/PCMU frames protected with SRTP-SDES
 *    (AES_CM_128_HMAC_SHA1_80) toward the remote RTP host.
 */
const tls = require("tls");
const dgram = require("dgram");
const https = require("https");
const crypto = require("crypto");
const md5 = (s) => crypto.createHash("md5").update(s, "ascii").digest("hex");

let hmm; void hmm; // reserved

/* ------------------------------------------------------------------ helpers */

function publicIp() {
  return new Promise((resolve) => {
    const req = https.get("https://api.ipify.org", (res) => {
      let b = "";
      res.on("data", (d) => (b += d));
      res.on("end", () => resolve(b.trim() || "127.0.0.1"));
    });
    req.setTimeout(5000, () => req.destroy());
    req.on("error", () => resolve("127.0.0.1"));
  });
}

/** G.711 μ-law (RFC 3551). 0xFF = silence, MSB set = positive. */
const ULAW_SEG_END = [0x0ff, 0x1ff, 0x3ff, 0x7ff, 0x0fff, 0x1fff, 0x3fff, 0x7fff];
function pcmuEncode(sample) {
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

/** G.711 mu-law bytes for a 440 Hz tone, one 20 ms frame at 8 kHz. */
function pcmuTone(frame = 160) {
  const out = Buffer.alloc(frame);
  const A = 4000;
  for (let i = 0; i < frame; i++) {
    const v = Math.sin((2 * Math.PI * 440 * i) / 8000) * A;
    out[i] = pcmuEncode(Math.max(-32124, Math.min(32124, v | 0)));
  }
  return out;
}

/* ------------------------------------------------------------------ SRTP */

/**
 * SRTP-SDES AES_CM_128_HMAC_SHA1_80 (RFC 3711) - mirrors the official
 * ringcentral-softphone-ts implementation the server validates against:
 *   - session keys are DERIVED from the 30-byte SDES material
 *     (RFC 3711 4.3 KDF: label 0->encryption(16), 1->authentication(20),
 *      2->salt(14))
 *   - only the RTP payload is encrypted (aes-128-ctr); the whole 12-byte
 *     RTP header travels in clear
 *   - auth tag = first 10 bytes of HMAC-SHA1(key=derived auth key) over the
 *     on-wire packet + 4-byte rollover counter
 */
const AUTH_TAG_LENGTH = 10;

function aesBlock(key, input) {
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(input), cipher.final()]);
}

function deriveKey(masterKey, masterSalt, label, length) {
  const input = Buffer.alloc(16);
  masterSalt.copy(input);
  input[7] ^= label;
  const parts = [];
  for (let block = 0; block * 16 < length; block++) {
    input.writeUInt16BE(block, 14);
    parts.push(aesBlock(masterKey, input));
  }
  return Buffer.concat(parts).subarray(0, length);
}

function deriveSessionKeys(keyMaterial) {
  const masterKey = keyMaterial.subarray(0, 16);
  const masterSalt = keyMaterial.subarray(16);
  return {
    encryption: deriveKey(masterKey, masterSalt, 0, 16),
    authentication: deriveKey(masterKey, masterSalt, 1, 20),
    salt: deriveKey(masterKey, masterSalt, 2, 14),
  };
}

function srtpCounter(ssrc, roc, seq, salt) {
  const value = Buffer.alloc(16);
  value.writeUInt32BE(ssrc >>> 0, 4);
  value.writeUInt32BE(roc >>> 0, 8);
  value.writeUInt32BE(((seq >>> 0) * 65536) >>> 0, 12);
  for (let i = 0; i < salt.length; i++) value[i] ^= salt[i];
  return value;
}

function srtpEncrypt(payload, ssrc, roc, seq, key, salt) {
  const cipher = crypto.createCipheriv("aes-128-ctr", key, srtpCounter(ssrc, roc, seq, salt));
  return Buffer.concat([cipher.update(payload), cipher.final()]);
}

function rtpHdr(seq, ssrc, marker, ts) {
  const b = Buffer.alloc(12);
  b[0] = 0x80;
  b[1] = (marker ? 0x80 : 0x00) | 0; // PT=0 PCMU
  b.writeUInt16BE(seq, 2);
  b.writeUInt32BE(ts >>> 0, 4);
  b.writeUInt32BE(ssrc >>> 0, 8);
  return b;
}

function parseRtpHeader(buf) {
  if (buf.length < 12 || buf[0] >> 6 !== 2) return null;
  const first = buf[0];
  let off = 12 + (first & 0x0f) * 4;
  if (off > buf.length) return null;
  if (first & 0x10) {
    if (off + 4 > buf.length) return null;
    off += 4 + buf.readUInt16BE(off + 2) * 4;
    if (off > buf.length) return null;
  }
  return {
    marker: (buf[1] & 0x80) !== 0,
    pt: buf[1] & 0x7f,
    seq: buf.readUInt16BE(2),
    ts: buf.readUInt32BE(4),
    ssrc: buf.readUInt32BE(8),
    payloadOffset: off,
    padding: (first & 0x20) !== 0,
  };
}

/**
 * Wraps per-direction session keys. use local 30-byte key for outbound and
 * the remote answer's 30-byte key for inbound.
 */
class Srtp {
  constructor(base64Key) {
    this.keys = deriveSessionKeys(Buffer.from(base64Key, "base64"));
    this.rtp = 0; // outbound rollover counter
    this.rtpIn = 0;
    this.inSsrc = 0;
    this.inSeqs = new Map();
  }

  /** Protect one outbound RTP packet with the given header; returns SRTP. */
  protect(hdr12, payload) {
    const seq = hdr12.readUInt16BE(2);
    const ssrc = hdr12.readUInt32BE(8);
    const enc = srtpEncrypt(payload, ssrc, this.rtp, seq, this.keys.encryption, this.keys.salt);
    const wire = Buffer.alloc(12 + enc.length);
    hdr12.copy(wire, 0, 0, 12);
    enc.copy(wire, 12);
    const roc = Buffer.alloc(4);
    roc.writeUInt32BE(this.rtp, 0);
    const tag = crypto.createHmac("sha1", this.keys.authentication).update(wire).update(roc).digest().subarray(0, AUTH_TAG_LENGTH);
    return Buffer.concat([wire, tag]);
  }

  /** Decrypt one inbound SRTP packet; returns clear RtpPacket or null. */
  unprotect(pkt) {
    try {
      if (pkt.length < 12 + AUTH_TAG_LENGTH) return null;
      const body = pkt.subarray(0, -AUTH_TAG_LENGTH);
      const h = parseRtpHeader(body);
      if (!h) return null;
      const roc = Buffer.alloc(4);
      let rocV = this.inSsrc === h.ssrc ? this.rtpIn : 0;
      roc.writeUInt32BE(rocV, 0);
      const expected = crypto.createHmac("sha1", this.keys.authentication).update(body).update(roc).digest().subarray(0, AUTH_TAG_LENGTH);
      if (!crypto.timingSafeEqual(expected, pkt.subarray(-AUTH_TAG_LENGTH))) return null;
      this.inSsrc = h.ssrc;
      if (h.seq < 0x8000 && rocV > 0) this.rtpIn = rocV; // keep monotonic-ish
      const payload = srtpEncrypt(body.subarray(h.payloadOffset), h.ssrc, rocV, h.seq, this.keys.encryption, this.keys.salt);
      return { header: h, payload };
    } catch {
      return null;
    }
  }
}

/* ------------------------------------------------------------------- UA */

/**
 * Make one unattended outgoing call over RingCentral SIP (TLS+SRTP).
 * o.user     = SIP username        o.pass  = SIP password
 * o.authId   = authorization id    o.domain= SIP domain
 * o.proxy    = outbound proxy host o.port  = proxy TLS port
 * o.number   = destination E.164   o.durationMs = sip time before BYE
 * o.codec    = "pcmu" (default) | "opus" (SDP offer differs)
 * Resolves with { ok, status, last, media, steps, extra }.
 */
function sipCallOnce(o) {
  return new Promise((resolve) => {
    const user = String(o.user || "");
    const pass = String(o.pass || "");
    const authId = String(o.authId || user);
    let domain = String(o.domain || "sip.ringcentral.com").replace(/:\d+$/, "");
    let proxy = String(o.proxy || "sip40.ringcentral.com").replace(/:\d+$/, "");
    let port = Number(o.port || 5096);
    const codec = o.codec === "opus" ? "opus" : "pcmu";
    const number = String(o.number || "").replace(/[^0-9+]/g, "");
    const duration = Math.max(1500, Number(o.durationMs || 4000));
    const steps = [];
    const st = {
      authUser: authId || user,
      nonce: null, qop: null, realm: null,
      phase: "register", sock: null, fromTag: null, toTag: null,
      callId: null, cseq: 0, registered: false,
    };
    let media = { ip: null, port: 0, key: null, remoteIp: null, remotePort: null, remoteKey: null, localAddr: null, localPort: null }, status = null, settled = false, outcome = "failed";
    let udp = null, rtpTimer = null, byeSent = false, acked = false;
    const ssrc = (crypto.randomBytes(4).readUInt32BE(0) & 0x7fffffff) | 0x80000000;
    const regAor = `sip:${user}@${domain}`;
    const regContact = `sip:${user}@${proxy}`;
    const raor = () => `sip:${number}@${domain}`;
    const from = () => `sip:${user}@${domain}`;

    // REGISTER uses the exact proven challenge-response shape (no qop -> md5
    // fallback), byte-compatible with the recipe that registers reliably.
    const regAuth = (method, uri) => {
      if (!st.nonce) return null;
      const HA1 = md5(`${st.authUser}:${domain}:${pass}`);
      let resp;
      if (st.qop) {
        const nc = "00000001", cn = crypto.randomBytes(4).toString("hex");
        resp = md5(`${HA1}:${st.nonce}:${nc}:${cn}:${st.qop}:${md5(method + ":" + uri)}`);
        return `Authorization: Digest username="${st.authUser}", realm="${st.realm || domain}", nonce="${st.nonce}", uri="${uri}", qop=${st.qop}, nc=${nc}, cnonce="${cn}", response="${resp}"`;
      }
      resp = md5(`${HA1}:${st.nonce}:${md5(method + ":" + uri)}`);
      return `Authorization: Digest username="${st.authUser}", realm="${st.realm || domain}", nonce="${st.nonce}", uri="${uri}", response="${resp}"`;
    };

    // INVITE/BYE carry Proxy-Authorization (SDK-proven digest form).
    const inviteDigest = (method) => {
      if (!st.nonce) return null;
      const HA1 = md5(`${st.authUser}:${domain}:${pass}`);
      const HA2 = md5(method + ":sip:" + domain);
      return `Proxy-Authorization: Digest algorithm="MD5", username="${st.authUser}", realm="${domain}", nonce="${st.nonce}", uri="sip:${domain}", response="${md5(`${HA1}:${st.nonce}:${HA2}`)}"`;
    };

    const buildRegister = (cseq) => [
      "REGISTER " + regAor + " SIP/2.0",
      "Via: SIP/2.0/TLS " + proxy + ";branch=z9hG4bK" + crypto.randomBytes(6).toString("hex"),
      "Max-Forwards: 70",
      "From: <" + regContact + ">;tag=" + crypto.randomBytes(6).toString("hex"),
      "To: <" + regContact + ">",
      "Call-ID: " + crypto.randomBytes(8).toString("hex"),
      "CSeq: " + cseq + " REGISTER",
      "Contact: <" + regContact + ">",
      "Expires: 300",
      "User-Agent: MagicDialer-SIP/0.1",
      regAuth("REGISTER", regAor),
      "Content-Length: 0",
      "",
      "",
    ].filter(Boolean).join("\r\n");

    const makeSdp = () => {
      const mt = codec === "opus" ? 109 : 0;
      const rn = codec === "opus" ? "OPUS/16000" : "PCMU/8000";
      const body = [
        "v=0",
        `o=- ${Date.now()} 0 IN IP4 ${media.ip}`,
        "s=rc-softphone-ts",
        `c=IN IP4 ${media.ip}`,
        "t=0 0",
        `m=audio ${media.port} RTP/SAVP ${mt} 101`,
        `a=rtpmap:${mt} ${rn}`,
        "a=rtpmap:101 telephone-event/8000",
        "a=fmtp:101 0-15",
        "a=sendrecv",
        `a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:${media.key}`,
      ].join("\r\n");
      return body + "\r\n";
    };

    const buildInvite = (cseq) => {
      const sdp = makeSdp();
      const h = [
        "INVITE " + raor() + " SIP/2.0",
        `Via: SIP/2.0/TLS ${media.localAddr}:${media.localPort};rport;branch=z9hG4bK-${crypto.randomUUID()};alias`,
        "Max-Forwards: 70",
        "From: <" + from() + ">;tag=" + st.fromTag,
        "To: <" + raor() + ">",
        "Call-ID: " + st.callId,
        "CSeq: " + cseq + " INVITE",
        `Contact: <sip:${user}@${media.localAddr}:${media.localPort};transport=TLS;ob>`,
        `Route: <sip:${proxy}:${port};transport=tls;lr>`,
        "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS",
        "Supported: replaces, 100rel, timer, norefersub",
        "Session-Expires: 1800",
        "Min-SE: 90",
        "Content-Type: application/sdp",
        "User-Agent: MagicDialer-SIP/0.1",
      ];
      const cid = String(o.callerId || "").replace(/[^0-9+]/g, "");
      if (cid) {
        h.push(`P-Asserted-Identity: <sip:${cid}@${domain}>`);
        h.push(`Remote-Party-ID: <sip:${cid}@${domain}>;party=calling;screen=yes;privacy=off`);
        h.push(`P-Preferred-Identity: <sip:${cid}@${domain}>`);
      }
      if (st.nonce) h.push(inviteDigest("INVITE"));
      h.push(`Content-Length: ${Buffer.byteLength(sdp)}`, "", sdp);
      return h.join("\r\n");
    };

    const buildAck = () => [
      "ACK " + raor() + " SIP/2.0",
      `Via: SIP/2.0/TLS ${media.localAddr}:${media.localPort};rport;branch=z9hG4bK-${crypto.randomUUID()};alias`,
      "Max-Forwards: 70",
      "From: <" + from() + ">;tag=" + st.fromTag,
      "To: <" + raor() + ">" + (st.toTag ? ";tag=" + st.toTag : ""),
      "Call-ID: " + st.callId,
      "CSeq: " + st.cseq + " ACK",
      "Content-Length: 0", "", "",
    ].join("\r\n");

    const buildBye = () => {
      const cseq = ++st.cseq;
      const toTag = st.toTag ? ";tag=" + st.toTag : "";
      return [
        "BYE " + raor() + " SIP/2.0",
        `Via: SIP/2.0/TLS ${media.localAddr}:${media.localPort};rport;branch=z9hG4bK-${crypto.randomUUID()};alias`,
        "Max-Forwards: 70",
        "From: <" + from() + ">;tag=" + st.fromTag,
        "To: <" + raor() + ">" + toTag,
        "Call-ID: " + st.callId,
        "CSeq: " + cseq + " BYE",
        inviteDigest("BYE"),
        "Content-Length: 0", "", "",
      ].filter(Boolean).join("\r\n");
    };

    /** Parse an SDP body for the remote RTP host / port / SDES crypto key. */
    const parseSdp = (body) => {
      const cm = body.match(/c=IN\s+IP4\s+([0-9.]+)/);
      const am = body.match(/m=audio\s+(\d+)\s/);
      const km = body.match(/a=crypto:1\s+AES_CM_128_HMAC_SHA1_80\s+inline:([\w+/]+)/);
      return {
        ip: cm ? cm[1] : null,
        port: am ? parseInt(am[1], 10) : null,
        key: km ? km[1] : null,
      };
    };

    const done = (ok, last, extra) => {
      if (settled) return;
      settled = true;
      try { clearInterval(rtpTimer); } catch {}
      try { if (udp) udp.close(); } catch {}
      try { if (st.sock) st.sock.destroy(); } catch {}
      resolve({ ok, status, outcome, media, steps, last, extra });
    };

    let outSrtp = null, inSrtp = null, rtpCount = 0;

    /** Lazily open the RTP socket + fetch public IP, needed only for INVITE. */
    const ensureMedia = async () => {
      if (media && media.port) return;
      const ip = await publicIp();
      media.ip = ip;
      if (!media.key) media.key = Buffer.concat([crypto.randomBytes(16), crypto.randomBytes(14)]).toString("base64");
      udp = dgram.createSocket("udp4");
      await new Promise((res) => udp.bind(0, "0.0.0.0", res));
      media.port = udp.address().port;
      outSrtp = new Srtp(media.key);
      udp.on("message", (msg) => {
        rtpCount++;
        media.lastRtpAt = new Date().toISOString();
        if (inSrtp && media.remoteIp) {
          try {
            const pkt = inSrtp.unprotect(msg);
            if (pkt) { media.inboundUnlocked = true; media.lastPayloadLen = pkt.payload.length; }
          } catch {}
        }
      });
    };

    let buf = "";
    const onData = async (d) => {
      if (process.env.SIP_DEBUG) console.log("[sip] data(" + d.length + "):", JSON.stringify(d.toString("ascii").slice(0, 180)));
      buf += d.toString("ascii");
      if (!buf.includes("\r\n\r\n")) return;
      const txt = buf;
      buf = "";
      const line = txt.split("\r\n")[0].trim();
      steps.push(line);
      const code = parseInt(line.split(" ")[1] || "", 10);
      const toTagM = txt.match(/[Tt]o:\s*<[^>]*>;tag=([^\s;]+)/);
      if (toTagM) st.toTag = toTagM[1];

      if (code === 100) return;

      if (code === 401 || code === 407) {
        if (!st.nonce) {
          st.nonce = (txt.match(/nonce="([^"]+)"/) || [])[1] || null;
          st.qop = (txt.match(/[Qq]op\s*=\s*"?([^"\s,]+)"?/) || [])[1] || null;
          st.realm = (txt.match(/[Rr]eal[mM]\s*=\s*"?([^"\s,]+)"?/) || [])[1] || null;
          if (st.nonce) steps.push("nonce");
        }
        if (!st.nonce) return done(false, line + " (no nonce)");
        if (st.phase === "register") st.sock.write(buildRegister(2));
        else if (st.phase === "invite") st.sock.write(buildInvite(st.cseq));
        return;
      }

      if (code === 180 || code === 183) {
        status = "ringing";
        if (code === 183) {
          const body = txt.split("\r\n\r\n").slice(1).join("\r\n\r\n");
          const sdp = parseSdp(body);
          if (sdp.ip && sdp.port && sdp.key) {
            media.remoteIp = sdp.ip;
            media.remotePort = sdp.port;
            media.remoteKey = sdp.key;
            inSrtp = new Srtp(sdp.key);
          }
          steps.push(`183 sdp ${sdp.ip || "-"}:${sdp.port || "-"} crypto=${!!sdp.key}`);
        }
        return;
      }

      if (code === 200) {
        if (st.phase === "register" && !st.registered) {
          st.registered = true;
          st.phase = "invite";
          st.fromTag = crypto.randomUUID();
          st.callId = crypto.randomBytes(8).toString("hex");
          st.cseq = 1;
          if (settled) return;
          try { await ensureMedia(); } catch (e) { return done(false, "media setup failed: " + e.message); }
          if (settled) return;
          st.sock.write(buildInvite(1));
          return;
        }
        if (st.phase === "invite") {
          status = "answered";
          outcome = "answered";
          // ACK once (200 to our INVITE)
          if (!acked) { acked = true; st.sock.write(buildAck()); steps.push("ACK"); }
          const body = txt.split("\r\n\r\n").slice(1).join("\r\n\r\n");
          if (body.includes("a=crypto:1") && !media.remoteKey) {
            const sdp = parseSdp(body);
            if (sdp.ip && sdp.port && sdp.key) {
              media.remoteIp = sdp.ip; media.remotePort = sdp.port; media.remoteKey = sdp.key;
              inSrtp = new Srtp(sdp.key);
            }
          }
          // stream the real script payloads (o.payloads = 20ms PCMU frames);
          // tone fallback only when no audio was supplied.
          const tones = o.payloads && Array.isArray(o.payloads) && o.payloads.length ? null : pcmuTone(160);
          const silence = Buffer.alloc(160, 0xff);
          let seq = crypto.randomBytes(2).readUInt16BE(0);
          let ts = (crypto.randomBytes(4).readUInt32BE(0));
          const start = Date.now();
          const sendFrame = () => {
            if (!media.remotePort || settled) return;
            if (!acked) { acked = true; st.sock.write(buildAck()); }
            let payload;
            if (tones) payload = tones;
            else {
              const idx = Math.floor((Date.now() - start) / 20);
              payload = idx < o.payloads.length ? o.payloads[idx] : silence;
            }
            const hdr = rtpHdr(seq, ssrc, seq === 0, ts);
            const pkt = outSrtp.protect(hdr, payload);
            try { udp.send(pkt, 0, pkt.length, media.remotePort, media.remoteIp); } catch {}
            seq = (seq + 1) & 0xffff;
            ts = (ts + 160) >>> 0;
            if (Date.now() - start >= duration) {
              clearInterval(rtpTimer);
              st.phase = "bye";
              if (!byeSent) { byeSent = true; st.sock.write(buildBye()); steps.push("BYE"); }
              setTimeout(() => done(true, "answered, streamed " + duration + "ms"), 600);
            }
          };
          rtpTimer = setInterval(sendFrame, 20);
          return;
        }
      }

      if (code >= 400 && code < 600) {
        if (code === 486 || code === 480 || code === 487) outcome = code === 486 ? "busy" : code === 480 ? "no-answer" : "failed";
        else if (code === 484 || code === 488) outcome = "failed";
        else outcome = "failed";
        return done(false, line);
      }
    };

    // ---------------- REGISTER first via the proven routine (opens the TLS
    // socket, does the byte-exact challenge->200 OK dance), then hand the
    // SAME socket over for the INVITE phase so the working session shape is
    // reused verbatim. Media comes up only after registration succeeds. -----
    (async () => {
      let reg;
      try { reg = await registerSession(o); } catch (e) { return done(false, "register error: " + e.message); }
      if (settled) return;
      if (!reg.ok || !reg.sock) return done(false, reg.last);
      const sock = reg.sock;
      st.sock = sock;
      st.nonce = reg.nonce;
      st.qop = reg.qop || null;
      st.realm = reg.realm || domain;
      media.localAddr = sock.localAddress;
      media.localPort = sock.localPort;
      try { await ensureMedia(); } catch (e) { return done(false, "media setup failed: " + e.message); }
      if (settled) return;
      steps.push(...reg.steps);
      st.registered = true;
      st.phase = "invite";
      st.fromTag = crypto.randomUUID();
      st.callId = crypto.randomBytes(8).toString("hex");
      st.cseq = 1;
      sock.on("data", onData);
      sock.on("timeout", () => done(false, "no response (network or firewall)"));
      sock.on("error", (e) => done(false, "connection error: " + e.message));
      if (process.env.SIP_DEBUG) console.log("[sip] registered; sending INVITE", st.fromTag.slice(0, 8), "media", media.ip + ":" + media.port);
      const inv = buildInvite(st.cseq);
      if (process.env.SIP_DEBUG) console.log("[sip] INVITE " + inv.length + " bytes:\n" + inv.replace(/\r\n/g, "\\r\\n\n"));
      sock.write(inv);
    })();
  });
}

/** The byte-exact, proven REGISTER routine (brute-force verified: 100 Trying,
 *  401 challenge, 100 Trying, 200 OK). On success hands back the OPEN, clean
 *  TLS socket so the caller can continue the session (SIP call) on it. */
function registerSession(o) {
  return new Promise((resolve) => {
    const HOST = String(o.proxy || "sip40.ringcentral.com");
    const PORT = Number(o.port || 5096);
    const user = String(o.user || "");
    const pass = String(o.pass || "");
    const domain = String(o.domain || "sip.ringcentral.com").replace(/:\d+$/, "");
    const digestUser = String(o.authId || user);
    const ruri = `sip:${user}@${domain}`;
    const contact = `sip:${user}@${HOST}`;
    const steps = [];
    let nonce = null, qop = null, realm = null, authed = false;
    const buildMsg = (cseq) => {
      const lines = [
        "REGISTER " + ruri + " SIP/2.0",
        `Via: SIP/2.0/TLS ${HOST};branch=z9hG4bK` + crypto.randomBytes(6).toString("hex"),
        "Max-Forwards: 70",
        `From: <${contact}>;tag=` + crypto.randomBytes(6).toString("hex"),
        `To: <${contact}>`,
        "Call-ID: " + crypto.randomBytes(8).toString("hex"),
        "CSeq: " + cseq + " REGISTER",
        `Contact: <${contact}>`,
        "Expires: 300",
        "User-Agent: MagicDialer-SIP/0.1",
      ];
      if (authed && nonce) {
        const HA1 = md5(`${digestUser}:${domain}:${pass}`);
        let resp;
        if (qop) {
          const nc = "00000001", cn = crypto.randomBytes(4).toString("hex");
          resp = md5(`${HA1}:${nonce}:${nc}:${cn}:${qop}:${md5("REGISTER:" + ruri)}`);
          lines.push(`Authorization: Digest username="${digestUser}", realm="${realm || domain}", nonce="${nonce}", uri="${ruri}", qop=${qop}, nc=${nc}, cnonce="${cn}", response="${resp}"`);
        } else {
          resp = md5(`${HA1}:${nonce}:${md5("REGISTER:" + ruri)}`);
          lines.push(`Authorization: Digest username="${digestUser}", realm="${realm || domain}", nonce="${nonce}", uri="${ruri}", response="${resp}"`);
        }
      }
      lines.push("Content-Length: 0", "", "");
      return lines.join("\r\n");
    };
    let settled = false;
    const sock = tls.connect({ port: PORT, host: HOST, servername: HOST, rejectUnauthorized: false }, () => sock.write(buildMsg(1)));
    const fail = (last) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardGate);
      sock.setTimeout(0);
      try { sock.destroy(); } catch {}
      resolve({ ok: false, steps, last, sock: null });
    };
    const succeed = () => {
      if (settled) return;
      settled = true;
      clearTimeout(hardGate);
      sock.setTimeout(0);
      if (dh) try { sock.removeListener("data", dh); } catch {}
      resolve({ ok: true, steps, last: "registered", sock, nonce, realm, qop });
    };
    const hardGate = setTimeout(() => fail("no response (network or firewall)"), 9000);
    sock.setTimeout(6000);
    let buf = "";
    const dh = (d) => {
      buf += d.toString("ascii");
      if (!buf.includes("\r\n\r\n")) return;
      const txt = buf; buf = "";
      const line = txt.split("\r\n")[0].trim();
      steps.push(line);
      const m = txt.match(/[Rr]eal[mM]\s*=\s*"?([^"\s,]+)"?/);
      if (m) realm = m[1];
      const qm = txt.match(/[Qq]op\s*=\s*"?([^"\s,]+)"?/);
      if (qm) qop = qm[1];
      if (/401|407/.test(line) && !authed) {
        authed = true;
        nonce = (txt.match(/[Nn]once\s*=\s*"?([^"\s,]+)"?/) || [])[1] || null;
        if (nonce) setTimeout(() => sock.write(buildMsg(2)), 150);
        else fail("no nonce");
      } else if (/200 OK/.test(line)) succeed();
      else if (/401|407/.test(line) && authed) fail("auth rejected");
      else if (/^SIP\/2\.0 (403|484)/.test(line)) fail(line);
    };
    sock.on("data", dh);
    sock.on("timeout", () => fail("sock timeout"));
    sock.on("error", (e) => fail("conn error: " + e.message));
  });
}

/** Register-only validation (closes the socket afterwards). */
async function rawReg(o) {
  const r = await registerSession(o);
  if (r.ok && r.sock) { try { r.sock.destroy(); } catch {} }
  return { ok: r.ok, steps: r.steps, last: r.last };
}

module.exports = { sipCallOnce, pcmuTone, rawReg, registerSession };