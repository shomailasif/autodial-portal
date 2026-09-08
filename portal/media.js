/*
 * Cloud call gateway - media channel (the "wire" that carries call audio).
 *
 * Customer PCs connect here over the SAME 443 surface as everything else
 * (WebSocket upgrade on the portal's HTTPS). No SIP, no RTP, no firewall
 * openings on any customer network. For now this is the control + audio
 * loopback transport:
 *
 *   agent --WSS(443)--> portal /ws/media/<callid>   (audio chunks both ways)
 *
 * Sim trunk behavior: the portal plays a canned greeting into the channel and
 * then echoes whatever the agent sends back (loopback), proving the full
 * 443 media path end to end without any carrier.
 *
 * Real carriers (RingCentral RingOut, Twilio, Asterisk...) will attach RTP
 * bridges to the same channel. Frame format is plain RFC6455 WebSocket.
 */
const crypto = require("node:crypto");

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const TEXT = 0x1;
const BINARY = 0x2;
const CLOSE = 0x8;
const PING = 0x9;
const PONG = 0xA;

// Incremental server-side frame decoder (handles frames split across TCP reads).
class Framer {
  constructor(onMessage, onClose) {
    this._buf = Buffer.alloc(0);
    this._onMessage = onMessage;
    this._onClose = onClose;
    this.closed = false;
  }
  push(chunk) {
    if (this.closed) return;
    this._buf = this._buf.length ? Buffer.concat([this._buf, chunk]) : chunk;
    for (;;) {
      const frame = this._parse();
      if (!frame) return;
      switch (frame.opcode) {
        case TEXT: this._onMessage(frame.payload, false); break;
        case BINARY: this._onMessage(frame.payload, true); break;
        case PING: this._onMessage(frame.payload, "ping"); break;
        case PONG: break;
        case CLOSE: this._close(); return;
        default: this._close(); return;
      }
      if (frame.fin !== undefined && !frame.fin) {
        // fragmented messages unsupported; drop the connection
        this._close();
        return;
      }
    }
  }
  _parse() {
    const b = this._buf;
    if (b.length < 2) return null;
    const fin = (b[0] & 0x80) !== 0;
    const opcode = b[0] & 0x0f;
    const masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f;
    let off = 2;
    if (len === 126) {
      if (b.length < 4) return null;
      len = b.readUInt16BE(2);
      off = 4;
    } else if (len === 127) {
      if (b.length < 10) return null;
      const hi = b.readUInt32BE(2);
      const lo = b.readUInt32BE(6);
      len = hi * 0x100000000 + lo;
      off = 10;
    }
    if (len > 128 * 1024) { this._close(); return null; } // safety cap per frame
    const maskBytes = masked ? 4 : 0;
    if (b.length < off + maskBytes + len) return null;
    const mask = masked ? b.subarray(off, off + 4) : null;
    const payload = Buffer.from(b.subarray(off + maskBytes, off + maskBytes + len));
    if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
    this._buf = b.subarray(off + maskBytes + len);
    return { fin, opcode, payload };
  }
  _close() {
    this.closed = true;
    this._buf = Buffer.alloc(0);
    this._onClose();
  }
}

function encodeFrame(opcode, payload, mask = false) {
  const pay = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const len = pay.length;
  const head = [0x80 | opcode];
  var off = 0;
  var ext = null;
  if (len < 126) head.push((mask ? 0x80 : 0) | len);
  else if (len < 65536) { head.push((mask ? 0x80 : 0) | 126); ext = Buffer.alloc(2); ext.writeUInt16BE(len, 0); off = 2; }
  else { head.push((mask ? 0x80 : 0) | 127); ext = Buffer.alloc(8); ext.writeUInt32BE(0, 0); ext.writeUInt32BE(len >>> 0, 4); off = 8; }
  let out = Buffer.concat([Buffer.from(head), ext ? ext : Buffer.alloc(0), pay]);
  if (mask) {
    const k = crypto.randomBytes(4);
    const masked = Buffer.alloc(pay.length);
    for (let i = 0; i < pay.length; i++) masked[i] = pay[i] ^ k[i & 3];
    out = Buffer.concat([Buffer.from(head), ext ? ext : Buffer.alloc(0), k, masked]);
  }
  return out;
}

const TONE_8K_16BIT = (() => {
  // Canned 8kHz mono 16-bit PCM "greeting": 0.35s of 440Hz + 0.35s silence.
  const n = 0.7 * 8000;
  const b = Buffer.alloc(n * 2);
  for (let i = 0; i < n; i++) {
    const t = i / 8000;
    const v = t < 0.35 ? Math.sin(2 * Math.PI * 440 * t) * 0.4 : 0;
    b.writeInt16LE(Math.round(v * 32767), i * 2);
  }
  return b;
})();

/**
 * install(server, { getSession, portalId })
 *  getSession(id) -> gateway call session (see trunk.js) or null.
 */
function install(server, { getSession }) {
  server.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url, "http://localhost");
    const m = String(url.pathname).match(/^\/ws\/media\/([^/]+)$/);
    if (!m) { socket.destroy(); return; }
    const sessionId = decodeURIComponent(m[1]);
    const key = req.headers["sec-websocket-key"];
    if (!key) { socket.destroy(); return; }
    const session = getSession(sessionId);
    const url2 = url;
    const token = (url2.searchParams.get("token") || "").toString();
    const accept = crypto.createHash("sha1").update(key + WS_GUID).digest("base64");
    // Always complete the handshake first - the client reads it to know the
    // channel is speaking WebSocket. Auth failures are then signalled with a
    // proper error frame + close instead of a silent socket drop.
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      "Sec-WebSocket-Accept: " + accept + "\r\n" +
      "Access-Control-Allow-Origin: *\r\n\r\n"
    );
    if (!session || !token || session.token !== token) {
      socket.write(encodeFrame(TEXT, JSON.stringify({ type: "error", error: "forbidden" })));
      socket.end(encodeFrame(CLOSE, Buffer.from([0x03, 0xf0])));
      return;
    }

    let attachedAt = Date.now();
    const media = {
      attachedAt,
      bytesIn: 0,
      bytesOut: 0,
      ended: false,
      send(payload, binary = true) {
        if (media.ended) return;
        const frame = encodeFrame(binary ? BINARY : TEXT, payload);
        media.bytesOut += frame.length;
        socket.write(frame);
      },
    };
    session.media = media;
    session.mediaActive = true;

    const framer = new Framer((payload, kind) => {
      if (kind === "ping") { socket.write(encodeFrame(PONG, payload)); return; }
      if (kind === true) {
        media.bytesIn += payload.length;
        session.mediaBytesIn = (session.mediaBytesIn || 0) + payload.length;
        if (session.provider === "sim") {
          // Loopback: echo what the agent sends back. The timestamp proves the
          // agent heard its own audio through the cloud 443 channel.
          const p = payload;
          setTimeout(() => { media.send(p); }, 250);
        }
        return;
      }
      // text control frame
      try {
        const j = JSON.parse(String(payload));
        if (j.type === "bye") { media.send(encodeFrame(CLOSE, Buffer.from([0x03, 0xe8]))); socket.end(); }
        else if (j.type === "status") socket.write(encodeFrame(TEXT, JSON.stringify({ type: "status", status: session.status })));
      } catch {}
    }, (onClosedNow) => {
      // local close path
    });

    socket.on("data", (d) => framer.push(d));
    socket.on("end", () => teardown());
    socket.on("error", () => teardown());
    socket.on("close", () => teardown());

    function teardown() {
      if (media.ended) return;
      media.ended = true;
      session.mediaActive = false;
      session.mediaBytesIn = session.mediaBytesIn || 0;
      session.mediaBytesOut = session.mediaBytesOut || 0;
    }

    // Sim: after attach, play the canned greeting through the channel.
    if (session.provider === "sim") {
      setTimeout(() => {
        if (!media.ended) media.send(TONE_8K_16BIT);
      }, 200);
    }
  });
}

function sendFrames(socket, frames) {
  for (const f of frames) socket.write(f);
}

module.exports = { install, encodeFrame };