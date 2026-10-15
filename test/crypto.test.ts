import { describe, expect, it } from "vitest";
import * as nodeCrypto from "node:crypto";
import { pkcs1v15Unpad, resolveKeyTransport, rsaDecrypt, rsaEncrypt } from "../src/crypto.js";
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

describe("RSA-OAEP key transport", () => {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const key = nodeCrypto.randomBytes(32);

  it.each([
    ["sha1", undefined],
    ["sha256", undefined],
    ["sha512", undefined],
    ["sha256", Buffer.from("scep label")],
  ] as const)("round-trips with %s (label %s)", (hash, label) => {
    const kt = resolveKeyTransport({ scheme: "rsa-oaep", hash, label });
    const ct = rsaEncrypt(publicKey, key, kt);
    expect(rsaDecrypt(privateKey, ct, 32, kt)).toEqual(key);
    // Independently decryptable with the same parameters.
    const plain = nodeCrypto.privateDecrypt(
      { key: privateKey, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: hash, oaepLabel: label },
      ct,
    );
    expect(plain).toEqual(key);
  });

  it("returns a random key of the expected length on decryption failure", () => {
    const kt = resolveKeyTransport("rsa-oaep");
    const ct = rsaEncrypt(publicKey, key, kt);
    const wrongHash = resolveKeyTransport({ scheme: "rsa-oaep", hash: "sha1" });
    const out = rsaDecrypt(privateKey, ct, 32, wrongHash);
    expect(out).toHaveLength(32);
    expect(out).not.toEqual(key);
    expect(rsaDecrypt(privateKey, ct, 16, kt)).toHaveLength(16); // length mismatch
    expect(() => rsaDecrypt(privateKey, ct, undefined, wrongHash)).toThrow(/decrypt/);
  });

  it("refuses key and hash combinations too small for the payload", () => {
    const small = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey;
    const kt = resolveKeyTransport({ scheme: "rsa-oaep", hash: "sha512" });
    expect(() => rsaEncrypt(small, key, kt)).toThrow(/at most 0 bytes/);
    expect(rsaEncrypt(small, key, resolveKeyTransport("rsa-oaep"))).toHaveLength(128);
  });
});
