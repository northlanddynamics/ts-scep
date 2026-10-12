import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { KeyObject, X509Certificate } from "node:crypto";
import { createCertificate, generateRsaKeyPair } from "../src/index.js";

export function hasOpenSsl(): boolean {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/** Run openssl in a scratch directory with the given input files; returns the named output files. */
export function openssl(
  args: string[],
  files: Record<string, string | Uint8Array> = {},
  outputs: string[] = [],
): { stdout: Buffer; files: Record<string, Buffer> } {
  const dir = mkdtempSync(join(tmpdir(), "ts-scep-"));
  try {
    for (const [name, data] of Object.entries(files)) writeFileSync(join(dir, name), data);
    const stdout = execFileSync("openssl", args, { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
    const out: Record<string, Buffer> = {};
    for (const name of outputs) out[name] = readFileSync(join(dir, name));
    return { stdout, files: out };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export interface TestCa {
  certificate: X509Certificate;
  privateKey: KeyObject;
}

export function makeCa(subject = "CN=Test Root CA,O=ts-scep,C=US"): TestCa {
  const { privateKey } = generateRsaKeyPair(2048);
  const certificate = createCertificate({
    subject,
    publicKey: privateKey,
    signingKey: privateKey,
    isCA: true,
    keyUsage: ["keyCertSign", "cRLSign", "digitalSignature", "keyEncipherment"],
  });
  return { certificate, privateKey };
}

export function pemKey(key: KeyObject): string {
  return key.export({ type: "pkcs8", format: "pem" }) as string;
}
