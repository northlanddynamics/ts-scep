import { describe, expect, it } from "vitest";
import * as nodeCrypto from "node:crypto";
import { pkcs1v15Unpad } from "../src/crypto.js";
import { CACapabilities } from "../src/index.js";

describe("pkcs1v15Unpad", () => {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const raw = (ct: Buffer) => nodeCrypto.privateDecrypt({ key: privateKey, padding: nodeCrypto.constants.RSA_NO_PADDING }, ct);

  it("recovers a PKCS #1 v1.5 encrypted key", () => {
    const key = nodeCrypto.randomBytes(16);
    const ct = nodeCrypto.publicEncrypt({ key: publicKey, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, key);
    expect(pkcs1v15Unpad(raw(ct), 16)).toEqual(key);
    expect(pkcs1v15Unpad(raw(ct))).toEqual(key);
    expect(pkcs1v15Unpad(raw(ct), 24)).toBeUndefined();
  });

  it("rejects malformed padding", () => {
    const em = Buffer.alloc(256, 1);
    expect(pkcs1v15Unpad(em)).toBeUndefined(); // wrong header
    em[0] = 0;
    em[1] = 2;
    expect(pkcs1v15Unpad(em)).toBeUndefined(); // no separator
    em[5] = 0;
    expect(pkcs1v15Unpad(em)).toBeUndefined(); // PS shorter than 8 bytes
  });
});

describe("CACapabilities", () => {
  it("parses case-insensitively and applies SCEPStandard implications", () => {
    const caps = CACapabilities.parse("scepstandard\r\nRenewal\r\n\r\n");
    expect(caps.supportsPost).toBe(true);
    expect(caps.supportsAes).toBe(true);
    expect(caps.supportsRenewal).toBe(true);
    expect(caps.digestAlgorithm).toBe("sha256");
    expect(caps.encryptionAlgorithm).toBe("aes-128-cbc");
    expect(CACapabilities.parse("SHA-512\nDES3").digestAlgorithm).toBe("sha512");
  });
});
