const fs = require("node:fs");
const path = require("node:path");

/**
 * Email sender for the portal. Sends good-lead emails to the customer's
 * address. Uses free SMTP configured via env vars (e.g. a Gmail/other free
 * account the customer provides).
 *
 * If no SMTP is configured, the email is written to an "outbox" file so the
 * system still proves it works with zero setup — and the portal can show it.
 */
function transporter() {
  const gh = process.env.SMTP_HOST;
  if (!gh) return null;
  try {
    // nodemailer lives in the project root's node_modules.
    const nm = require.resolve("nodemailer", { paths: [path.resolve(__dirname, "..", "..", "..", "..")] });
    // eslint-disable-next-line global-require
    const nodemailer = require(nm);
    return nodemailer.createTransport({
      host: gh,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === "true",
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
  } catch {
    return null;
  }
}

async function sendEmail({ to, subject, text }) {
  const t = transporter();
  if (t) {
    try {
      await t.sendMail({ from: process.env.SMTP_USER || "autodial@localhost", to, subject, text });
      return { delivered: true, to, subject };
    } catch (err) {
      // fall through to outbox so we don't lose the lead
      return writeOutbox({ to, subject, text, note: "SMTP failed: " + err.message });
    }
  }
  return writeOutbox({ to, subject, text, note: "No SMTP configured — recorded to outbox." });
}

function writeOutbox({ to, subject, text, note }) {
  const dir = process.env.AUTODIAL_OUTBOX || path.join("outbox");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `lead-${Date.now()}.txt`);
  fs.writeFileSync(file, `TO: ${to}\nSUBJECT: ${subject}\nNOTE: ${note}\n\n${text}\n`, "utf8");
  return { delivered: false, to, subject, outboxFile: file };
}

function listOutbox() {
  const dir = process.env.AUTODIAL_OUTBOX || path.join("outbox");
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).map((f) => ({ file: f, content: fs.readFileSync(path.join(dir, f), "utf8") }));
}

module.exports = { sendEmail, listOutbox };
