/**
 * Enrol a certificate from a SCEP server.
 *
 *   SCEP_URL=http://ca.example.com/cgi-bin/pkiclient.exe \
 *   SCEP_CHALLENGE=secret \
 *   SCEP_CA_FINGERPRINT=AB:CD:... \
 *   npx tsx examples/enroll.ts device-01
 */
import { writeFileSync } from "node:fs";
import { PkiStatus, ScepClient, ScepFailureError, createCsr, generateRsaKeyPair } from "../src/index.js";

const cn = process.argv[2] ?? "device-01";
const client = new ScepClient({
  url: process.env.SCEP_URL ?? "http://127.0.0.1:8080/scep",
  caFingerprint: process.env.SCEP_CA_FINGERPRINT,
});

const caps = await client.getCACaps();
console.log("CA capabilities:", caps.keywords.join(", "));
const ca = await client.getCACert();
console.log("CA:", ca.ca.subject.replace(/\n/g, ", "), "SHA-256", ca.ca.fingerprint256);

const { privateKey } = generateRsaKeyPair(2048);
const csr = createCsr({
  subject: `CN=${cn}`,
  privateKey,
  challengePassword: process.env.SCEP_CHALLENGE,
  subjectAltNames: { dns: [cn] },
});

try {
  let result = await client.enroll({ csr, privateKey });
  if (result.status === PkiStatus.PENDING) {
    console.log(`Request ${result.transactionId} is pending approval; polling…`);
    result = await client.waitForCertificate(result.pending, { intervalMs: 30_000, timeoutMs: 3_600_000 });
  }
  writeFileSync(`${cn}.key`, privateKey.export({ type: "pkcs8", format: "pem" }));
  writeFileSync(`${cn}.crt`, result.certificate.toString());
  console.log(`Issued ${result.certificate.subject} (serial ${result.certificate.serialNumber})`);
} catch (err) {
  if (err instanceof ScepFailureError) console.error("CA rejected the request:", err.message);
  else throw err;
  process.exitCode = 1;
}
