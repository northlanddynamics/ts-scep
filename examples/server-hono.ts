/**
 * The example CA from server.ts, served by Hono on Bun.
 *
 *   bun examples/server-hono.ts     # then point any SCEP client at http://127.0.0.1:8080/scep
 */
import { timingSafeEqual } from "node:crypto";
import { Hono } from "hono";
import { FailInfo, ScepServer, createCertificate, createCrl, generateRsaKeyPair } from "../src/index.js";

const CHALLENGE = process.env.SCEP_CHALLENGE ?? "secret";

const { privateKey: caKey } = generateRsaKeyPair(3072);
const caCert = createCertificate({
  subject: "CN=Example SCEP CA,O=Example,C=US",
  publicKey: caKey,
  signingKey: caKey,
  isCA: true,
  keyUsage: ["keyCertSign", "cRLSign", "digitalSignature", "keyEncipherment"],
  notAfter: new Date(Date.now() + 5 * 365 * 86_400_000),
});

const passwordOk = (given?: string) =>
  given !== undefined &&
  given.length === CHALLENGE.length &&
  timingSafeEqual(Buffer.from(given), Buffer.from(CHALLENGE));

const scep = new ScepServer({
  ca: { certificate: caCert, privateKey: caKey },
  maxClockSkewMs: 10 * 60_000,
  maxBodyBytes: 256 * 1024, // PKIOperation bodies larger than this get HTTP 413
  handler: {
    enroll(req) {
      const authorised = req.renewal ? req.signerIssuedByCa : passwordOk(req.csr.challengePassword);
      if (!authorised) {
        return { status: "failure", failInfo: FailInfo.badRequest, failInfoText: "Not authorised" };
      }
      const cert = createCertificate({
        subject: req.csr.subject,
        publicKey: req.csr.publicKey,
        signingKey: caKey,
        issuer: caCert,
        extensions: req.csr.extensions,
        keyUsage: ["digitalSignature", "keyEncipherment"],
        extendedKeyUsage: ["1.3.6.1.5.5.7.3.2"],
      });
      console.log(`issued ${cert.subject} serial=${cert.serialNumber} tid=${req.transactionId}`);
      return { status: "success", certificates: [cert] };
    },
    getCRL() {
      return { status: "success", crls: [createCrl({ issuer: caCert, signingKey: caKey })] };
    },
  },
});

const app = new Hono();
// Mount ahead of any middleware that reads the body, or pass the bytes it read:
//   scep.handleFetch(c.req.raw, { body: new Uint8Array(await c.req.arrayBuffer()) })
app.all("/scep", (c) => scep.fetchHandler(c.req.raw));
app.all("/cgi-bin/pkiclient.exe", (c) => scep.fetchHandler(c.req.raw));

console.log("SCEP server on http://127.0.0.1:8080/scep");
console.log("CA fingerprint (SHA-256):", caCert.fingerprint256);

export default { port: 8080, fetch: app.fetch };
