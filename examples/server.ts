/**
 * A minimal SCEP CA: auto-issues certificates to requests carrying the right challenge password.
 *
 *   npx tsx examples/server.ts      # then point any SCEP client at http://127.0.0.1:8080/scep
 */
import { createServer } from "node:http";
import { timingSafeEqual } from "node:crypto";
import {
  FailInfo,
  ScepServer,
  createCertificate,
  createCrl,
  generateRsaKeyPair,
} from "../src/index.js";

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
const issued = new Map<string, ReturnType<typeof createCertificate>>();

const passwordOk = (given?: string) =>
  given !== undefined &&
  given.length === CHALLENGE.length &&
  timingSafeEqual(Buffer.from(given), Buffer.from(CHALLENGE));

const scep = new ScepServer({
  ca: { certificate: caCert, privateKey: caKey },
  maxClockSkewMs: 10 * 60_000,
  handler: {
    enroll(req) {
      // Renewals are authorised by the existing certificate; new enrolments by the challenge.
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
      issued.set(cert.serialNumber.toLowerCase(), cert);
      console.log(`issued ${cert.subject} serial=${cert.serialNumber} tid=${req.transactionId}`);
      return { status: "success", certificates: [cert] };
    },
    getCert(req) {
      const cert = issued.get(req.serialNumber.toString("hex"));
      return cert ? { status: "success", certificates: [cert] } : { status: "failure", failInfo: FailInfo.badCertId };
    },
    getCRL() {
      return { status: "success", crls: [createCrl({ issuer: caCert, signingKey: caKey })] };
    },
  },
});

const handler = scep.nodeHandler();
createServer((req, res) => {
  if (req.url?.startsWith("/scep") || req.url?.startsWith("/cgi-bin/pkiclient.exe")) return handler(req, res);
  res.writeHead(404).end();
}).listen(8080, () => {
  console.log("SCEP server on http://127.0.0.1:8080/scep");
  console.log("CA fingerprint (SHA-256):", caCert.fingerprint256);
});
