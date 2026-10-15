import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import {
  PkiStatus,
  ScepClient,
  ScepServer,
  createCertificate,
  createCrl,
  createCsr,
  generateRsaKeyPair,
  type ScepClientOptions,
} from "../src/index.js";
import { makeCa } from "./helpers.js";

/** Bun's `serve()`, when running under Bun. */
const bunServe = (globalThis as { Bun?: { serve(opts: object): { port: number; stop(force?: boolean): Promise<void> } } }).Bun?.serve;

const ca = makeCa();
const scep = new ScepServer({
  ca,
  handler: {
    enroll: (req) => ({
      status: "success",
      certificates: [
        createCertificate({ subject: req.csr.subject, publicKey: req.csr.publicKey, signingKey: ca.privateKey, issuer: ca.certificate }),
      ],
    }),
    getCRL: () => ({ status: "success", crls: [createCrl({ issuer: ca.certificate, signingKey: ca.privateKey })] }),
  },
});

const app = new Hono();
app.all("/scep", (c) => scep.fetchHandler(c.req.raw));
app.all("/cgi-bin/pkiclient.exe", (c) => scep.fetchHandler(c.req.raw));
// Middleware that consumes the body: hand the bytes over instead of the spent stream.
app.all("/limited", bodyLimit({ maxSize: 64 * 1024 }), async (c) =>
  scep.handleFetch(c.req.raw, { body: new Uint8Array(await c.req.arrayBuffer()) }),
);

describe(`SCEP behind Hono (${bunServe ? "Bun.serve" : "app.fetch"})`, () => {
  let base = "http://scep.test";
  let fetchImpl: ScepClientOptions["fetch"] = (input, init) => Promise.resolve(app.fetch(new Request(input, init)));
  let stop = async () => {};

  beforeAll(() => {
    if (!bunServe) return;
    const server = bunServe({ port: 0, hostname: "127.0.0.1", fetch: app.fetch });
    base = `http://127.0.0.1:${server.port}`;
    fetchImpl = undefined;
    stop = () => server.stop(true);
  });
  afterAll(() => stop());

  const enroll = async (path: string, opts: Partial<ScepClientOptions> = {}) => {
    const client = new ScepClient({ url: base + path, caFingerprint: ca.certificate.fingerprint256, fetch: fetchImpl, ...opts });
    const { privateKey } = generateRsaKeyPair();
    const csr = createCsr({ subject: "CN=hono-device", privateKey, challengePassword: "x" });
    return client.enroll({ csr, privateKey });
  };

  it.each<[string, Partial<ScepClientOptions>]>([
    ["AES-128", { encryptionAlgorithm: "aes-128-cbc" }],
    ["AES-256 / SHA-512", { encryptionAlgorithm: "aes-256-cbc", digestAlgorithm: "sha512" }],
    ["3DES / SHA-1", { encryptionAlgorithm: "des-ede3-cbc", digestAlgorithm: "sha1" }],
    ["DES (legacy CA)", { capabilities: ["SHA-1"], encryptionAlgorithm: "des-cbc" }],
    ["RSA-OAEP", { keyTransport: "rsa-oaep" }],
    ["GET PKIOperation", { usePost: false }],
  ])("enrols with %s", async (_, opts) => {
    const result = await enroll("/scep", opts);
    if (result.status !== PkiStatus.SUCCESS) throw new Error(`expected success, got ${result.status}`);
    expect(result.certificate.subject).toContain("hono-device");
  });

  it("serves the legacy path and a body pre-read by middleware", async () => {
    expect((await enroll("/cgi-bin/pkiclient.exe")).status).toBe(PkiStatus.SUCCESS);
    expect((await enroll("/limited")).status).toBe(PkiStatus.SUCCESS);
  });

  const post = (path: string, body: Uint8Array | ReadableStream<Uint8Array>, headers: Record<string, string> = {}) =>
    (fetchImpl ?? fetch)(`${base}${path}?operation=PKIOperation`, {
      method: "POST",
      body,
      headers: { "content-type": "application/x-pki-message", ...headers },
      ...(body instanceof ReadableStream ? { duplex: "half" } : {}),
    } as RequestInit);

  it("rejects oversized PKIOperation bodies with 413", async () => {
    expect((await post("/scep", new Uint8Array(2 * 1024 * 1024))).status).toBe(413);
    // Chunked, no Content-Length: the limit applies while streaming.
    const chunk = new Uint8Array(256 * 1024);
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (sent++ < 8) controller.enqueue(chunk);
        else controller.close();
      },
    });
    expect((await post("/scep", stream)).status).toBe(413);
    expect((await post("/limited", new Uint8Array(128 * 1024))).status).toBe(413);
  });

  it("applies a per-request limit", async () => {
    const res = await scep.handleFetch(
      new Request(`${base}/scep?operation=PKIOperation`, { method: "POST", body: new Uint8Array(2048) }),
      { maxBodyBytes: 1024 },
    );
    expect(res.status).toBe(413);
  });
});
