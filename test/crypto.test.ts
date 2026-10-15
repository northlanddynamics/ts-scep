import { describe, expect, it } from "vitest";
import * as nodeCrypto from "node:crypto";
import { implicitRejectionKdk, pkcs1v15DecodeImplicit, resolveKeyTransport, rsaDecrypt, rsaEncrypt } from "../src/crypto.js";
import { CACapabilities } from "../src/index.js";

// Known answer from OpenSSL 3.5's native implicit rejection (1024-bit key, invalid ciphertext).
const KAT_KEY = `-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAL68zTJpf44ZLJdt
FFrXWRhQPTa6FQoVKUvLDITvwi13AEQls96zTygAP6SMWjGMWl+FN5MUNrWd6yOI
7JAg4CjKngDMZsf8lH+a0q0ImgtFFOMQQ65qFgtR4y0v5MX5w6vYfsjOm9APi8Ql
AfqK5EOJ+ggdJM/1Zu7sqyuHYs5xAgMBAAECgYByIifncpmRPh8gvXTgptv5YIpA
pTjRv7fmUqo7Ifzfl8XhAW6QZFuJZByxKgsOex3Y6q5GpGHYa5a4vMZRuFppBZrS
93vTDmPXZ9KODDY3JATQipPnBL2KVl0Jb807Q6OUYBt/VHdDh1u/oYav9mbKrrgY
3CMQtTaqcB8Wa7ztAQJBAOdDjrusqDD/Z2VdnlrbCHexNuqkHnAfXrS3tMia+ScO
i6xYI3880Quh1nYwYUIpmckc62V6bTn5f8MTBNwqsEUCQQDTI44KyA0jEGipVB4/
1wMMgHhYWwjerFBcksUWnI3wsP/6ihVHE6M3GP0N7covMzAkEgR1Q4aboJ2Y33Id
C3Y9AkEAteg/94OB8LiVPfh7vP+ZE30Ds2FQx+UE+6WcwEaWQJCCcRgLI+RUko/E
P8ciWYabfsQOrQ21qOqGAo2NPxkc+QJAUV+AnPMg7QSj8a6zwdLyH91bhGIBdyBe
EG+YefB4W+07mqmhLbWJz/BXhwjARZSq1xwCj9coh85NLt/fMQZ72QJBAJGCyE4Q
AOZkzIGNznoqkVCRmrI5G//z7IRXY33ssi8hDmB67lGmZGOCu4H48NmDauXWpFgm
eRyykRL86D5NXXY=
-----END PRIVATE KEY-----`;
const KAT_CT =
  "00d5c214fdb04b36e7d28edfe1af3a67e60a0f8c5734b48674295c5a7bd082d3fafe0ed05fdd13ab0e6f6c222da17f37" +
  "2466f6a3d130bb961b58e4573cdb6099211607c40b3cdd319d3d6f46742a3e544834a04110f300854bee45cc51cf74ca" +
  "24189da1589fb7d55dbf5acbb98bae5a7ccf2050953aae0b18b539181f235738";
const KAT_OUT =
  "c2ae29e5362a96563a339a19a7a4c3d2a905e15432d571a3b6c721152f8edd0e43ab4198333ab11934b2b70cdeaea727" +
  "6bb0c20cbebdca7d779091678a587f87b10487d52ceb34c1d35bf7efac14b04c55f96ecba3ec988a052347f8fa77ea31" +
  "12d3ad4be7be2a415707ab9b";

/** Whether this runtime decrypts PKCS #1 v1.5 natively with implicit rejection (vs. refusing). */
function nativeImplicitRejection(key: nodeCrypto.KeyObject): boolean {
  try {
    nodeCrypto.privateDecrypt({ key, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, Buffer.alloc(128, 0x55));
    return true;
  } catch {
    return false;
  }
}

describe("PKCS #1 v1.5 implicit rejection", () => {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const raw = (ct: Buffer) => nodeCrypto.privateDecrypt({ key: privateKey, padding: nodeCrypto.constants.RSA_NO_PADDING }, ct);
  const decode = (ct: Buffer) => pkcs1v15DecodeImplicit(raw(ct), implicitRejectionKdk(privateKey, ct));
  const encrypt = (m: Buffer) => nodeCrypto.publicEncrypt({ key: publicKey, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, m);

  it("recovers a PKCS #1 v1.5 encrypted key", () => {
    const key = nodeCrypto.randomBytes(16);
    const ct = encrypt(key);
    expect(decode(ct)).toEqual(key);
    expect(rsaDecrypt(privateKey, ct)).toEqual(key);
    expect(rsaDecrypt(privateKey, ct, 16)).toEqual(key);
  });

  it("matches the OpenSSL known answer on every runtime", () => {
    const key = nodeCrypto.createPrivateKey(KAT_KEY);
    const ct = Buffer.from(KAT_CT, "hex");
    const em = nodeCrypto.privateDecrypt({ key, padding: nodeCrypto.constants.RSA_NO_PADDING }, ct);
    expect(pkcs1v15DecodeImplicit(em, implicitRejectionKdk(key, ct)).toString("hex")).toBe(KAT_OUT);
    expect(rsaDecrypt(key, ct).toString("hex")).toBe(KAT_OUT);
  });

  it("returns a deterministic synthetic message for malformed padding", () => {
    const em = Buffer.alloc(256, 1);
    const kdk = nodeCrypto.randomBytes(32);
    const reject = pkcs1v15DecodeImplicit(em, kdk);
    expect(reject).toEqual(pkcs1v15DecodeImplicit(em, kdk));
    em[0] = 0;
    em[1] = 2;
    expect(pkcs1v15DecodeImplicit(em, kdk)).toEqual(reject); // no separator
    em[5] = 0;
    expect(pkcs1v15DecodeImplicit(em, kdk)).toEqual(reject); // PS shorter than 8 bytes
    em[5] = 1;
    em[10] = 0;
    expect(pkcs1v15DecodeImplicit(em, kdk)).toEqual(em.subarray(11)); // now well-formed
  });

  it("substitutes a deterministic key when the length is wrong", () => {
    const ct = encrypt(nodeCrypto.randomBytes(16));
    const out = rsaDecrypt(privateKey, ct, 24);
    expect(out).toHaveLength(24);
    expect(rsaDecrypt(privateKey, ct, 24)).toEqual(out);
    const garbage = Buffer.from(nodeCrypto.randomBytes(256));
    garbage[0] = 0;
    expect(rsaDecrypt(privateKey, garbage, 16)).toEqual(rsaDecrypt(privateKey, garbage, 16));
  });

  it.runIf(nativeImplicitRejection(privateKey))("agrees with the native implementation", () => {
    for (let n = 0; n < 64; n++) {
      const ct = n % 4 === 0 ? encrypt(nodeCrypto.randomBytes(n % 48)) : Buffer.from(nodeCrypto.randomBytes(256));
      ct[0] = n % 4 === 0 ? ct[0]! : 0;
      const native = nodeCrypto.privateDecrypt({ key: privateKey, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, ct);
      expect(decode(ct)).toEqual(native);
    }
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
