/**
 * Interoperability tests against sscep (https://github.com/certnanny/sscep), an independent
 * C implementation of a SCEP client. Enabled when SSCEP_BIN points at an sscep binary.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { X509Certificate } from "node:crypto";
import {
  FailInfo,
  ScepServer,
  createCertificate,
  createCrl,
  createCsr,
  derToPem,
  generateRsaKeyPair,
  type EnrollmentRequest,
  type ScepResult,
} from "../src/index.js";
import { makeCa, pemKey } from "./helpers.js";

const run = promisify(execFile);
const SSCEP = process.env.SSCEP_BIN;

describe.runIf(!!SSCEP)("interop with sscep", () => {
  const ca = makeCa("CN=Interop CA,O=ts-scep");
  const crl = createCrl({ issuer: ca.certificate, signingKey: ca.privateKey });
  const issued = new Map<string, X509Certificate>();
  let pollsBeforeApproval = 0;
  let lastEnroll: EnrollmentRequest | undefined;

  const issue = (req: EnrollmentRequest): ScepResult => {
    const cert = createCertificate({
      subject: req.csr.subject,
      publicKey: req.csr.publicKey,
      signingKey: ca.privateKey,
      issuer: ca.certificate,
    });
    issued.set(cert.serialNumber.toLowerCase(), cert);
    return { status: "success", certificates: [cert] };
  };
  const pending = new Map<string, EnrollmentRequest>();

  const server = new ScepServer({
    ca,
    handler: {
      enroll(req) {
        lastEnroll = req;
        if (req.csr.challengePassword !== "secret") return { status: "failure", failInfo: FailInfo.badRequest };
        if (req.csr.subjectString.includes("manual")) {
          pending.set(req.transactionId, req);
          pollsBeforeApproval = 2;
          return { status: "pending" };
        }
        return issue(req);
      },
      poll(req) {
        const p = pending.get(req.transactionId);
        if (!p) return { status: "failure", failInfo: FailInfo.badCertId };
        if (pollsBeforeApproval-- > 0) return { status: "pending" };
        return issue(p);
      },
      getCert(req) {
        const cert = issued.get(req.serialNumber.toString("hex"));
        return cert ? { status: "success", certificates: [cert] } : { status: "failure", failInfo: FailInfo.badCertId };
      },
      getCRL: () => ({ status: "success", crls: [crl] }),
    },
  });

  let http: Server;
  let url: string;
  let dir: string;
  const file = (name: string) => join(dir, name);
  const sscep = (...args: string[]) => run(SSCEP!, args, { cwd: dir, timeout: 30_000 });

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "ts-scep-sscep-"));
    http = createServer(server.nodeHandler());
    await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
    url = `http://127.0.0.1:${(http.address() as AddressInfo).port}/cgi-bin/pkiclient.exe`;
  });
  afterAll(async () => {
    await new Promise<void>((r) => http.close(() => r()));
    rmSync(dir, { recursive: true, force: true });
  });

  function request(cn: string) {
    const { privateKey } = generateRsaKeyPair();
    writeFileSync(file(`${cn}.key`), pemKey(privateKey));
    writeFileSync(
      file(`${cn}.csr`),
      derToPem(createCsr({ subject: `CN=${cn}`, privateKey, challengePassword: "secret" }), "CERTIFICATE REQUEST"),
    );
    return privateKey;
  }

  it("getcaps", async () => {
    const { stdout } = await sscep("getcaps", "-u", url);
    expect(stdout).toMatch(/SCEPStandard|AES/i);
  });

  it("getca", async () => {
    await sscep("getca", "-u", url, "-c", file("ca.crt"));
    expect(new X509Certificate(readFileSync(file("ca.crt"))).raw).toEqual(ca.certificate.raw);
  });

  it.each([
    ["aes", "sha256"],
    ["aes256", "sha512"],
    ["3des", "sha1"],
  ])("enroll (%s, %s)", async (enc, sig) => {
    const cn = `sscep-${enc}-${sig}`;
    request(cn);
    await sscep(
      "enroll", "-u", url, "-c", file("ca.crt"), "-k", file(`${cn}.key`), "-r", file(`${cn}.csr`),
      "-l", file(`${cn}.crt`), "-E", enc!, "-S", sig!,
    );
    const cert = new X509Certificate(readFileSync(file(`${cn}.crt`)));
    expect(cert.subject).toBe(`CN=${cn}`);
    expect(cert.verify(ca.certificate.publicKey)).toBe(true);
    expect(lastEnroll?.message.digestAlgorithm).toBe(sig);
  });

  it("enroll with manual approval (polling)", async () => {
    request("manual");
    await sscep(
      "enroll", "-u", url, "-c", file("ca.crt"), "-k", file("manual.key"), "-r", file("manual.csr"),
      "-l", file("manual.crt"), "-t", "1", "-n", "10",
    );
    expect(new X509Certificate(readFileSync(file("manual.crt"))).subject).toBe("CN=manual");
  });

  it("getcert and getcrl", async () => {
    const cert = new X509Certificate(readFileSync(file("sscep-aes-sha256.crt")));
    const serial = BigInt(`0x${cert.serialNumber}`).toString();
    await sscep(
      "getcert", "-u", url, "-c", file("ca.crt"), "-k", file("sscep-aes-sha256.key"),
      "-l", file("sscep-aes-sha256.crt"), "-O", file("ca.crt"), "-s", serial, "-w", file("fetched.crt"),
    );
    expect(new X509Certificate(readFileSync(file("fetched.crt"))).raw).toEqual(cert.raw);

    await sscep(
      "getcrl", "-u", url, "-c", file("ca.crt"), "-k", file("sscep-aes-sha256.key"),
      "-l", file("sscep-aes-sha256.crt"), "-O", file("sscep-aes-sha256.crt"), "-w", file("ca.crl"),
    );
    expect(readFileSync(file("ca.crl"), "latin1")).toContain("BEGIN X509 CRL");
  });

  it("re-enrolment signed with an existing certificate", async () => {
    request("rekey");
    await sscep(
      "enroll", "-u", url, "-c", file("ca.crt"), "-k", file("rekey.key"), "-r", file("rekey.csr"),
      "-K", file("sscep-aes-sha256.key"), "-O", file("sscep-aes-sha256.crt"), "-l", file("rekey.crt"),
    );
    expect(new X509Certificate(readFileSync(file("rekey.crt"))).subject).toBe("CN=rekey");
    expect(lastEnroll?.signerIssuedByCa).toBe(true);
  });
});
