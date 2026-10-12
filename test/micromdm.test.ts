/**
 * Interoperability tests of ScepClient against micromdm/scep (https://github.com/micromdm/scep),
 * an independent Go SCEP server. Enabled when SCEPSERVER_BIN points at a `scepserver` binary.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FailInfo, PkiStatus, ScepClient, ScepFailureError, createCsr, generateRsaKeyPair } from "../src/index.js";

const BIN = process.env.SCEPSERVER_BIN;

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer().listen(0, "127.0.0.1", () => {
      const { port } = s.address() as { port: number };
      s.close(() => resolve(port));
    });
  });
}

describe.runIf(!!BIN)("ScepClient interop with micromdm/scep", () => {
  let dir: string;
  let proc: ChildProcess;
  let url: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "ts-scep-micromdm-"));
    execFileSync(BIN!, ["ca", "-init", "-depot", join(dir, "depot")], { stdio: "ignore" });
    const port = await freePort();
    proc = spawn(
      BIN!,
      ["-depot", join(dir, "depot"), "-http-addr", `127.0.0.1:${port}`, "-challenge", "secret", "-allowrenew", "0"],
      { stdio: "ignore" },
    );
    url = `http://127.0.0.1:${port}/scep`;
    for (let i = 0; i < 100; i++) {
      try {
        if ((await fetch(`${url}?operation=GetCACaps`)).ok) return;
      } catch {
        /* not up yet */
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error("scepserver did not start");
  });

  afterAll(() => {
    proc?.kill();
    rmSync(dir, { recursive: true, force: true });
  });

  const csrFor = (cn: string, challengePassword = "secret") => {
    const { privateKey } = generateRsaKeyPair();
    return { privateKey, csr: createCsr({ subject: `CN=${cn},O=Interop`, privateKey, challengePassword }) };
  };

  it("discovers capabilities and CA certificate", async () => {
    const client = new ScepClient({ url });
    const caps = await client.getCACaps();
    expect(caps.supportsPost).toBe(true);
    const certs = await client.getCACert();
    expect(certs.ca.ca).toBe(true);
  });

  it.each([
    { name: "negotiated (POST)", opts: {} },
    { name: "GET", opts: { usePost: false } },
    { name: "DES3 + SHA-1", opts: { encryptionAlgorithm: "des-ede3-cbc" as const, digestAlgorithm: "sha1" as const } },
  ])("enrols ($name)", async ({ name, opts }) => {
    const client = new ScepClient({ url, ...opts });
    const cn = `ts-${name.replace(/\W+/g, "-")}`;
    const result = await client.enroll(csrFor(cn));
    expect(result.status).toBe(PkiStatus.SUCCESS);
    if (result.status !== PkiStatus.SUCCESS) return;
    const ca = (await client.getCACert()).ca;
    expect(result.certificate.subject).toContain(`CN=${cn}`);
    expect(result.certificate.verify(ca.publicKey)).toBe(true);
  });

  it("surfaces a CA rejection as ScepFailureError", async () => {
    const client = new ScepClient({ url });
    const err = await client.enroll(csrFor("ts-bad", "wrong")).catch((e) => e);
    expect(err).toBeInstanceOf(ScepFailureError);
    expect(err.failInfo).toBe(FailInfo.badRequest);
  });

  it("re-enrols with an existing certificate", async () => {
    const client = new ScepClient({ url });
    const first = csrFor("ts-renew");
    const issued = await client.enroll(first);
    if (issued.status !== PkiStatus.SUCCESS) throw new Error("expected success");
    const again = await client.enroll({
      ...csrFor("ts-renew"),
      signer: { certificate: issued.certificate, privateKey: first.privateKey },
    });
    expect(again.status).toBe(PkiStatus.SUCCESS);
  });
});
