import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { X509Certificate } from "node:crypto";
import {
  Capability,
  ContentTypes,
  FailInfo,
  MessageType,
  PkiStatus,
  ScepClient,
  ScepFailureError,
  ScepServer,
  createCertificate,
  createCrl,
  createCsr,
  createSelfSignedCertificate,
  encodePkiMessage,
  decodePkiMessage,
  generateRsaKeyPair,
  nameToString,
  type ScepHandler,
  type ScepResult,
  type EnrollmentRequest,
} from "../src/index.js";
import { makeCa, type TestCa } from "./helpers.js";

const CHALLENGE = "letmein";

/** A tiny in-memory CA used as the handler in tests. */
class MemoryCa implements ScepHandler {
  issued = new Map<string, X509Certificate>(); // serial hex -> cert
  pending = new Map<string, EnrollmentRequest>(); // transactionId -> request
  lastRequest?: EnrollmentRequest;
  manualApproval = false;
  crl: Buffer;

  constructor(public ca: TestCa) {
    this.crl = createCrl({ issuer: ca.certificate, signingKey: ca.privateKey });
  }

  issue(req: EnrollmentRequest): ScepResult {
    const cert = createCertificate({
      subject: req.csr.subject,
      publicKey: req.csr.publicKey,
      signingKey: this.ca.privateKey,
      issuer: this.ca.certificate,
      extensions: req.csr.extensions,
      extendedKeyUsage: ["1.3.6.1.5.5.7.3.2"],
    });
    this.issued.set(cert.serialNumber.toLowerCase(), cert);
    return { status: "success", certificates: [cert, this.ca.certificate] };
  }

  enroll(req: EnrollmentRequest): ScepResult {
    this.lastRequest = req;
    if (!req.renewal && req.csr.challengePassword !== CHALLENGE) {
      return { status: "failure", failInfo: FailInfo.badRequest, failInfoText: "Invalid challenge password" };
    }
    if (this.manualApproval) {
      this.pending.set(req.transactionId, req);
      return { status: "pending" };
    }
    return this.issue(req);
  }

  poll(req: { transactionId: string }): ScepResult {
    const p = this.pending.get(req.transactionId);
    if (!p) return { status: "failure", failInfo: FailInfo.badCertId };
    if (this.manualApproval) return { status: "pending" };
    this.pending.delete(req.transactionId);
    return this.issue(p);
  }

  getCert(req: { serialNumber: Buffer }): ScepResult {
    const cert = this.issued.get(req.serialNumber.toString("hex"));
    return cert ? { status: "success", certificates: [cert] } : { status: "failure", failInfo: FailInfo.badCertId };
  }

  getCRL(): ScepResult {
    return { status: "success", crls: [this.crl] };
  }
}

async function listen(server: ScepServer): Promise<{ http: Server; url: string }> {
  const http = createServer(server.nodeHandler());
  await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
  const { port } = http.address() as AddressInfo;
  return { http, url: `http://127.0.0.1:${port}/cgi-bin/pkiclient.exe` };
}

function newRequest(cn = "device-1", challengePassword: string | undefined = CHALLENGE) {
  const { privateKey } = generateRsaKeyPair();
  const csr = createCsr({
    subject: `CN=${cn},O=Example`,
    privateKey,
    challengePassword,
    subjectAltNames: { dns: [`${cn}.example.com`] },
  });
  return { privateKey, csr };
}

describe("SCEP over HTTP (CA mode)", () => {
  const ca = makeCa();
  const store = new MemoryCa(ca);
  const server = new ScepServer({ ca, handler: store });
  let http: Server;
  let url: string;

  beforeAll(async () => ({ http, url } = await listen(server)));
  afterAll(() => new Promise<void>((r) => http.close(() => r())));

  it("GetCACaps", async () => {
    const caps = await new ScepClient({ url }).getCACaps();
    expect(caps.has(Capability.SCEPStandard)).toBe(true);
    expect(caps.has("aes")).toBe(true);
    expect(caps.supportsPost).toBe(true);
    expect(caps.digestAlgorithm).toBe("sha256");
  });

  it("GetCACert returns the CA certificate", async () => {
    const res = await fetch(`${url}?operation=GetCACert`);
    expect(res.headers.get("content-type")).toBe(ContentTypes.caCert);
    const certs = await new ScepClient({ url }).getCACert();
    expect(certs.ca.raw).toEqual(ca.certificate.raw);
    expect(certs.encryptionCertificate.raw).toEqual(ca.certificate.raw);
  });

  it("checks the CA fingerprint", async () => {
    await expect(new ScepClient({ url, caFingerprint: "00".repeat(32) }).getCACert()).rejects.toThrow(/fingerprint/);
    const ok = new ScepClient({ url, caFingerprint: ca.certificate.fingerprint256 });
    await expect(ok.getCACert()).resolves.toBeDefined();
  });

  it.each([
    { name: "POST, AES, SHA-256", opts: {} },
    { name: "GET", opts: { usePost: false } },
    { name: "DES3 + SHA-1", opts: { encryptionAlgorithm: "des-ede3-cbc" as const, digestAlgorithm: "sha1" as const } },
    { name: "AES-256 + SHA-512", opts: { encryptionAlgorithm: "aes-256-cbc" as const, digestAlgorithm: "sha512" as const } },
  ])("enrols with PKCSReq ($name)", async ({ opts }) => {
    const client = new ScepClient({ url, ...opts });
    const { privateKey, csr } = newRequest();
    const result = await client.enroll({ csr, privateKey });
    expect(result.status).toBe(PkiStatus.SUCCESS);
    if (result.status !== PkiStatus.SUCCESS) return;
    expect(result.certificate.subject).toContain("CN=device-1");
    expect(result.certificate.verify(ca.certificate.publicKey)).toBe(true);
    expect(result.certificate.subjectAltName).toContain("device-1.example.com");
    expect(result.certificates).toHaveLength(2);
    expect(store.lastRequest?.selfSigned).toBe(true);
    expect(store.lastRequest?.message.messageType).toBe(MessageType.PKCSReq);
    if (opts.encryptionAlgorithm) expect(store.lastRequest?.message.encryptionAlgorithm).toBe(opts.encryptionAlgorithm);
  });

  it.each([
    { name: "SHA-256", keyTransport: "rsa-oaep" as const, expected: { scheme: "rsa-oaep", hash: "sha256" } },
    { name: "SHA-1", keyTransport: { scheme: "rsa-oaep" as const, hash: "sha1" as const }, expected: { scheme: "rsa-oaep", hash: "sha1" } },
  ])("enrols with RSA-OAEP key transport ($name)", async ({ keyTransport, expected }) => {
    const client = new ScepClient({ url, keyTransport });
    const { privateKey, csr } = newRequest("device-oaep");
    const result = await client.enroll({ csr, privateKey });
    expect(result.status).toBe(PkiStatus.SUCCESS);
    expect(store.lastRequest?.message.keyTransport).toEqual(expected);
  });

  it("mirrors the request's key transport in the CertRep envelope", async () => {
    const { privateKey, csr } = newRequest("device-mirror");
    const self = createSelfSignedCertificate({ subject: "CN=device-mirror", privateKey });
    for (const keyTransport of ["rsa-pkcs1", { scheme: "rsa-oaep", hash: "sha384" }] as const) {
      const req = encodePkiMessage({
        messageType: MessageType.PKCSReq,
        transactionId: "MIRROR",
        messageData: csr,
        recipient: ca.certificate,
        signer: { certificate: self, privateKey },
        keyTransport,
      });
      const rep = decodePkiMessage(await server.pkiOperation(req), { recipient: { certificate: self, privateKey } });
      expect(rep.pkiStatus).toBe(PkiStatus.SUCCESS);
      expect(rep.keyTransport).toEqual(keyTransport);
    }
  });

  it("rejects a bad challenge password with failInfo", async () => {
    const client = new ScepClient({ url });
    const { privateKey, csr } = newRequest("device-2", "wrong");
    const err = await client.enroll({ csr, privateKey }).catch((e) => e);
    expect(err).toBeInstanceOf(ScepFailureError);
    expect(err.failInfo).toBe(FailInfo.badRequest);
    expect(err.failInfoText).toBe("Invalid challenge password");
  });

  it("handles manual approval with CertPoll", async () => {
    const client = new ScepClient({ url });
    const { privateKey, csr } = newRequest("device-3");
    store.manualApproval = true;
    try {
      const first = await client.enroll({ csr, privateKey });
      expect(first.status).toBe(PkiStatus.PENDING);
      if (first.status !== PkiStatus.PENDING) return;
      expect(nameToString(first.pending.subject)).toBe("CN=device-3,O=Example");

      const second = await client.poll(first.pending);
      expect(second.status).toBe(PkiStatus.PENDING);

      store.manualApproval = false;
      const done = await client.waitForCertificate(first.pending, { intervalMs: 10, timeoutMs: 5_000 });
      expect(done.certificate.subject).toContain("CN=device-3");
    } finally {
      store.manualApproval = false;
    }
  });

  it("renews with RenewalReq signed by the existing certificate", async () => {
    const client = new ScepClient({ url });
    const first = newRequest("device-4");
    const issued = await client.enroll(first);
    if (issued.status !== PkiStatus.SUCCESS) throw new Error("expected success");

    const next = newRequest("device-4", undefined);
    const renewed = await client.enroll({
      ...next,
      signer: { certificate: issued.certificate, privateKey: first.privateKey },
    });
    expect(renewed.status).toBe(PkiStatus.SUCCESS);
    expect(store.lastRequest?.renewal).toBe(true);
    expect(store.lastRequest?.signerIssuedByCa).toBe(true);
    expect(store.lastRequest?.message.messageType).toBe(MessageType.RenewalReq);
  });

  it("rejects RenewalReq signed with a self-signed certificate", async () => {
    const client = new ScepClient({ url });
    const { privateKey, csr } = newRequest("device-5");
    const err = await client.enroll({ csr, privateKey, renewal: true }).catch((e) => e);
    expect(err).toBeInstanceOf(ScepFailureError);
    expect(err.failInfo).toBe(FailInfo.badRequest);
  });

  it("retrieves certificates (GetCert) and CRLs (GetCRL)", async () => {
    const client = new ScepClient({ url });
    const req = newRequest("device-6");
    const issued = await client.enroll(req);
    if (issued.status !== PkiStatus.SUCCESS) throw new Error("expected success");
    const signer = { certificate: issued.certificate, privateKey: req.privateKey };

    const certs = await client.getCert({ serialNumber: Buffer.from(issued.certificate.serialNumber, "hex"), signer });
    expect(certs[0]!.raw).toEqual(issued.certificate.raw);

    const missing = await client.getCert({ serialNumber: Buffer.from([0x7f, 0x7f]), signer }).catch((e) => e);
    expect(missing).toBeInstanceOf(ScepFailureError);
    expect(missing.failInfo).toBe(FailInfo.badCertId);

    const crl = await client.getCRL({ signer });
    expect(crl).toEqual(store.crl);
  });

  it("answers a tampered request with a signed badMessageCheck CertRep", async () => {
    const { privateKey, csr } = newRequest("device-7");
    const self = createSelfSignedCertificate({ subject: "CN=device-7", privateKey });
    const msg = encodePkiMessage({
      messageType: MessageType.PKCSReq,
      transactionId: "TAMPERED",
      messageData: csr,
      recipient: ca.certificate,
      signer: { certificate: self, privateKey },
    });
    // Corrupt the RSA signature (last bytes of the message).
    msg[msg.length - 1] ^= 0xff;
    const res = await fetch(`${url}?operation=PKIOperation`, {
      method: "POST",
      headers: { "content-type": ContentTypes.pkiMessage },
      body: msg,
    });
    expect(res.status).toBe(200);
    const rep = decodePkiMessage(Buffer.from(await res.arrayBuffer()));
    expect(rep.pkiStatus).toBe(PkiStatus.FAILURE);
    expect(rep.failInfo).toBe(FailInfo.badMessageCheck);
    expect(rep.transactionId).toBe("TAMPERED");
    expect(rep.signerCertificate.raw).toEqual(ca.certificate.raw);
  });

  it("returns HTTP 400 for garbage and unknown operations", async () => {
    expect((await fetch(`${url}?operation=Nope`)).status).toBe(400);
    const res = await fetch(`${url}?operation=PKIOperation`, { method: "POST", body: Buffer.from("garbage") });
    expect(res.status).toBe(400);
  });
});

describe("SCEP server key-transport policy", () => {
  const ca = makeCa();
  const { privateKey, csr } = newRequest("device-policy");
  const self = createSelfSignedCertificate({ subject: "CN=device-policy", privateKey });
  const request = (keyTransport: "rsa-pkcs1" | "rsa-oaep") =>
    encodePkiMessage({
      messageType: MessageType.PKCSReq,
      transactionId: "POLICY",
      messageData: csr,
      recipient: ca.certificate,
      signer: { certificate: self, privateKey },
      keyTransport,
    });
  const decode = (der: Buffer) => decodePkiMessage(der, { recipient: { certificate: self, privateKey } });

  it("rejects RSAES-PKCS1-v1_5 requests with badAlg when OAEP is required", async () => {
    const server = new ScepServer({ ca, handler: new MemoryCa(ca), requireOaep: true });
    const rejected = decode(await server.pkiOperation(request("rsa-pkcs1")));
    expect(rejected.pkiStatus).toBe(PkiStatus.FAILURE);
    expect(rejected.failInfo).toBe(FailInfo.badAlg);
    expect(decode(await server.pkiOperation(request("rsa-oaep"))).pkiStatus).toBe(PkiStatus.SUCCESS);
  });

  it("uses a configured response key transport instead of mirroring", async () => {
    const server = new ScepServer({ ca, handler: new MemoryCa(ca), keyTransport: "rsa-oaep" });
    const rep = decode(await server.pkiOperation(request("rsa-pkcs1")));
    expect(rep.keyTransport).toEqual({ scheme: "rsa-oaep", hash: "sha256" });
  });
});

describe("SCEP with a registration authority", () => {
  const root = makeCa("CN=Root CA");
  const raKey = generateRsaKeyPair().privateKey;
  const raCert = createCertificate({
    subject: "CN=SCEP RA",
    publicKey: raKey,
    signingKey: root.privateKey,
    issuer: root.certificate,
    keyUsage: ["digitalSignature", "keyEncipherment"],
    isCA: false,
  });
  const store = new MemoryCa(root);
  const nextKey = generateRsaKeyPair().privateKey;
  const nextCa = createCertificate({ subject: "CN=Root CA G2", publicKey: nextKey, signingKey: nextKey, isCA: true });
  const server = new ScepServer({
    ca: root,
    ra: { certificate: raCert, privateKey: raKey },
    nextCaCertificates: [nextCa],
    handler: store,
  });

  it("serves CA+RA certificates and routes encryption via the RA", async () => {
    // Use the fetch adapter instead of a real socket.
    const client = new ScepClient({
      url: "http://scep.test/scep",
      fetch: (input, init) => server.fetchHandler(new Request(input, init)),
    });
    const certs = await client.getCACert();
    expect(certs.ca.raw).toEqual(root.certificate.raw);
    expect(certs.ra.map((c) => c.raw)).toEqual([raCert.raw]);
    expect(certs.encryptionCertificate.raw).toEqual(raCert.raw);

    const { privateKey, csr } = newRequest("ra-device");
    const result = await client.enroll({ csr, privateKey });
    if (result.status !== PkiStatus.SUCCESS) throw new Error("expected success");
    expect(result.response.signerCertificate.raw).toEqual(raCert.raw);
    expect(result.certificate.verify(root.certificate.publicKey)).toBe(true);

    const caps = await client.getCACaps();
    expect(caps.supportsGetNextCACert).toBe(true);
    const next = await client.getNextCACert();
    expect(next.map((c) => c.raw)).toEqual([nextCa.raw]);
  });

  it("rejects a CertRep signed by an untrusted party", async () => {
    const rogue = makeCa("CN=Rogue");
    const rogueServer = new ScepServer({ ca: rogue, handler: store });
    const client = new ScepClient({
      url: "http://scep.test/scep",
      caCertificates: [root.certificate],
      capabilities: ["POSTPKIOperation", "AES", "SHA-256"],
      fetch: (input, init) => rogueServer.fetchHandler(new Request(input, init)),
    });
    const { privateKey, csr } = newRequest("victim");
    await expect(client.enroll({ csr, privateKey })).rejects.toThrow(/not found|not signed|decrypt|recipient/i);
  });
});

describe("legacy servers", () => {
  it("treats a missing GetCACaps as no capabilities and falls back to GET/DES3/SHA-1", async () => {
    const ca = makeCa();
    const store = new MemoryCa(ca);
    const server = new ScepServer({ ca, handler: store });
    const seen: string[] = [];
    const client = new ScepClient({
      url: "http://legacy.test/cgi-bin/pkiclient.exe",
      fetch: async (input, init) => {
        const u = new URL(String(input));
        seen.push(`${init?.method ?? "GET"} ${u.searchParams.get("operation")}`);
        if (u.searchParams.get("operation") === "GetCACaps") return new Response("Not found", { status: 404 });
        return server.fetchHandler(new Request(input, init));
      },
    });
    const caps = await client.getCACaps();
    expect(caps.keywords).toEqual([]);
    expect(caps.encryptionAlgorithm).toBe("des-ede3-cbc");
    expect(caps.digestAlgorithm).toBe("sha1");
    const result = await client.enroll(newRequest("legacy"));
    expect(result.status).toBe(PkiStatus.SUCCESS);
    expect(seen).toContain("GET PKIOperation");
    expect(store.lastRequest?.message.encryptionAlgorithm).toBe("des-ede3-cbc");
    expect(store.lastRequest?.message.digestAlgorithm).toBe("sha1");
  });
});
