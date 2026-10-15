import * as nodeCrypto from "node:crypto";
import type { KeyObject } from "node:crypto";
import type { DigestAlgorithm, EncryptionAlgorithm, KeyTransportAlgorithm } from "./constants.js";
import { FailInfo } from "./constants.js";
import { ScepProtocolError } from "./errors.js";
import { OID } from "./oids.js";
import { toBuffer, type BytesLike } from "./util.js";

/** Private keys may be given as KeyObjects, PEM text or PKCS#8 DER. */
export type PrivateKeyLike = KeyObject | string | Uint8Array;
/** Public keys may be given as KeyObjects, PEM text or SPKI DER. */
export type PublicKeyLike = KeyObject | string | Uint8Array;

export function toPrivateKey(key: PrivateKeyLike): KeyObject {
  if (typeof key === "string") return nodeCrypto.createPrivateKey(key);
  if (key instanceof Uint8Array) return nodeCrypto.createPrivateKey({ key: toBuffer(key), format: "der", type: "pkcs8" });
  if (key.type !== "private") throw new TypeError("Expected a private key");
  return key;
}

export function toPublicKey(key: PublicKeyLike): KeyObject {
  if (typeof key === "string") return nodeCrypto.createPublicKey(key);
  if (key instanceof Uint8Array) return nodeCrypto.createPublicKey({ key: toBuffer(key), format: "der", type: "spki" });
  return key.type === "private" ? nodeCrypto.createPublicKey(key) : key;
}

/** Generate an RSA key pair suitable for SCEP (RSA is required for CMS key transport). */
export function generateRsaKeyPair(modulusLength = 2048): { publicKey: KeyObject; privateKey: KeyObject } {
  return nodeCrypto.generateKeyPairSync("rsa", { modulusLength, publicExponent: 0x10001 });
}

// ---------------------------------------------------------------------------
// Digests and signatures
// ---------------------------------------------------------------------------

export const DIGEST_OIDS: Record<DigestAlgorithm, string> = {
  sha1: OID.sha1,
  sha256: OID.sha256,
  sha384: OID.sha384,
  sha512: OID.sha512,
};

export const RSA_SIGNATURE_OIDS: Record<DigestAlgorithm, string> = {
  sha1: OID.sha1WithRSAEncryption,
  sha256: OID.sha256WithRSAEncryption,
  sha384: OID.sha384WithRSAEncryption,
  sha512: OID.sha512WithRSAEncryption,
};

const ECDSA_SIGNATURE_OIDS: Record<string, DigestAlgorithm> = {
  "1.2.840.10045.4.1": "sha1",
  "1.2.840.10045.4.3.2": "sha256",
  "1.2.840.10045.4.3.3": "sha384",
  "1.2.840.10045.4.3.4": "sha512",
};

export function digestAlgorithmFromOid(oid: string): DigestAlgorithm {
  for (const [name, value] of Object.entries(DIGEST_OIDS)) if (value === oid) return name as DigestAlgorithm;
  for (const [name, value] of Object.entries(RSA_SIGNATURE_OIDS)) if (value === oid) return name as DigestAlgorithm;
  const ec = ECDSA_SIGNATURE_OIDS[oid];
  if (ec) return ec;
  throw new ScepProtocolError(`Unsupported digest algorithm ${oid}`, FailInfo.badAlg);
}

/**
 * Determine the digest used by a signature algorithm identifier, falling back to the
 * separately-specified digest algorithm (CMS signerInfos commonly use plain rsaEncryption).
 */
export function signatureDigest(signatureOid: string, fallback: DigestAlgorithm): DigestAlgorithm {
  if (signatureOid === OID.rsaEncryption) return fallback;
  return digestAlgorithmFromOid(signatureOid);
}

export function digest(algorithm: DigestAlgorithm, data: BytesLike): Buffer {
  return nodeCrypto.createHash(algorithm).update(toBuffer(data)).digest();
}

export function sign(algorithm: DigestAlgorithm, key: KeyObject, data: BytesLike): Buffer {
  if (key.asymmetricKeyType === "rsa") {
    return nodeCrypto.sign(algorithm, toBuffer(data), { key, padding: nodeCrypto.constants.RSA_PKCS1_PADDING });
  }
  return nodeCrypto.sign(algorithm, toBuffer(data), key);
}

export function verify(algorithm: DigestAlgorithm, key: KeyObject, data: BytesLike, signature: BytesLike): boolean {
  try {
    if (key.asymmetricKeyType === "rsa") {
      return nodeCrypto.verify(
        algorithm,
        toBuffer(data),
        { key, padding: nodeCrypto.constants.RSA_PKCS1_PADDING },
        toBuffer(signature),
      );
    }
    return nodeCrypto.verify(algorithm, toBuffer(data), key, toBuffer(signature));
  } catch {
    return false;
  }
}

/** Signature algorithm OID for a key and digest (used for X.509 certificates, CRLs and CSRs). */
export function signatureAlgorithmOid(key: KeyObject, algorithm: DigestAlgorithm): string {
  if (key.asymmetricKeyType === "rsa") return RSA_SIGNATURE_OIDS[algorithm];
  if (key.asymmetricKeyType === "ec") {
    for (const [oid, alg] of Object.entries(ECDSA_SIGNATURE_OIDS)) if (alg === algorithm) return oid;
  }
  throw new ScepProtocolError(`Unsupported key type ${key.asymmetricKeyType}`, FailInfo.badAlg);
}

// ---------------------------------------------------------------------------
// RSA key transport
// ---------------------------------------------------------------------------

/** A key-transport scheme with its defaults filled in. */
export type ResolvedKeyTransport = { scheme: "rsa-pkcs1" } | { scheme: "rsa-oaep"; hash: DigestAlgorithm; label: Buffer };

export function resolveKeyTransport(algorithm: KeyTransportAlgorithm = "rsa-pkcs1"): ResolvedKeyTransport {
  if (algorithm === "rsa-pkcs1") return { scheme: "rsa-pkcs1" };
  if (algorithm === "rsa-oaep") return { scheme: "rsa-oaep", hash: "sha256", label: Buffer.alloc(0) };
  if (algorithm.scheme !== "rsa-oaep") throw new TypeError(`Unknown key transport scheme ${String(algorithm.scheme)}`);
  return { scheme: "rsa-oaep", hash: algorithm.hash ?? "sha256", label: toBuffer(algorithm.label ?? new Uint8Array()) };
}

const HASH_LENGTH: Record<DigestAlgorithm, number> = { sha1: 20, sha256: 32, sha384: 48, sha512: 64 };

function oaepOptions(key: KeyObject, kt: { hash: DigestAlgorithm; label: Buffer }) {
  return {
    key,
    padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: kt.hash,
    ...(kt.label.length ? { oaepLabel: kt.label } : {}),
  };
}

export function rsaEncrypt(key: KeyObject, data: BytesLike, keyTransport: ResolvedKeyTransport = { scheme: "rsa-pkcs1" }): Buffer {
  if (key.asymmetricKeyType !== "rsa") {
    throw new ScepProtocolError("SCEP key transport requires an RSA recipient key", FailInfo.badAlg);
  }
  if (keyTransport.scheme === "rsa-oaep") {
    const input = toBuffer(data);
    const k = Math.ceil((key.asymmetricKeyDetails?.modulusLength ?? 0) / 8);
    const max = k - 2 * HASH_LENGTH[keyTransport.hash] - 2;
    if (input.length > max) {
      throw new ScepProtocolError(
        `RSA-OAEP with ${keyTransport.hash} and a ${k * 8}-bit key can carry at most ${Math.max(max, 0)} bytes, not ${input.length}`,
        FailInfo.badAlg,
      );
    }
    return nodeCrypto.publicEncrypt(oaepOptions(key, keyTransport), input);
  }
  return nodeCrypto.publicEncrypt({ key, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, toBuffer(data));
}

/**
 * Decrypt a content-encryption key. As with PKCS #1 v1.5, an OAEP decoding failure is turned
 * into a random key of the expected length (when known) so that every failure surfaces as the
 * same content-decryption error, leaving no padding oracle (Manger's attack).
 */
export function rsaDecrypt(
  key: KeyObject,
  data: BytesLike,
  expectedLength?: number,
  keyTransport: ResolvedKeyTransport = { scheme: "rsa-pkcs1" },
): Buffer {
  if (keyTransport.scheme === "rsa-pkcs1") return rsaPkcs1Decrypt(key, data, expectedLength);
  let message: Buffer | undefined;
  try {
    message = nodeCrypto.privateDecrypt(oaepOptions(key, keyTransport), toBuffer(data));
  } catch (err) {
    if (!expectedLength) {
      throw new ScepProtocolError("Unable to decrypt content-encryption key", FailInfo.badMessageCheck, { cause: err });
    }
  }
  if (message && (expectedLength === undefined || message.length === expectedLength)) return message;
  if (expectedLength) return nodeCrypto.randomBytes(expectedLength);
  throw new ScepProtocolError("Unable to decrypt content-encryption key", FailInfo.badMessageCheck);
}

/**
 * RSAES-PKCS1-v1_5 decryption with implicit rejection (draft-irtf-cfrg-rsa-guidance §7.2), so that
 * a padding error is indistinguishable from a wrong key (Bleichenbacher / Marvin attacks): a
 * malformed ciphertext deterministically yields a synthetic message derived from the private key
 * and the ciphertext, and the failure only surfaces later as a content-decryption error.
 *
 * Node.js with OpenSSL 3.2+ implements implicit rejection natively. Runtimes that refuse PKCS #1
 * v1.5 private decryption (Bun, Node.js on older OpenSSL) use raw RSA plus the same algorithm,
 * implemented below without data-dependent branches, so both paths return the same bytes.
 *
 * When `expectedLength` is given, a result of any other length is replaced, again without
 * branching, by a synthetic key of that length.
 */
function rsaPkcs1Decrypt(key: KeyObject, data: BytesLike, expectedLength?: number): Buffer {
  const input = toBuffer(data);
  const kdk = implicitRejectionKdk(key, input);
  let message: Buffer;
  try {
    message = nodeCrypto.privateDecrypt({ key, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, input);
  } catch (err) {
    if (!/no longer supported/i.test(String((err as Error).message))) {
      throw new ScepProtocolError("Unable to decrypt content-encryption key", FailInfo.badMessageCheck, { cause: err });
    }
    let em: Buffer;
    try {
      em = nodeCrypto.privateDecrypt({ key, padding: nodeCrypto.constants.RSA_NO_PADDING }, input);
    } catch (rawErr) {
      throw new ScepProtocolError("Unable to decrypt content-encryption key", FailInfo.badMessageCheck, { cause: rawErr });
    }
    message = pkcs1v15DecodeImplicit(em, kdk);
  }
  if (expectedLength === undefined) return message;
  const synthetic = rsaPrf(kdk, "ts-scep cek", expectedLength);
  const lengthOk = ctEq(message.length, expectedLength);
  const out = Buffer.alloc(expectedLength);
  for (let i = 0; i < expectedLength; i++) out[i] = ctSelect(lengthOk, message[i] ?? 0, synthetic[i]!);
  return out;
}

const kdkKeys = new WeakMap<KeyObject, { hash: Buffer; length: number }>();

/**
 * Key-derivation key for implicit rejection: HMAC-SHA256 keyed with SHA-256 of the private
 * exponent (big-endian, modulus length), over the ciphertext left-padded to the modulus length.
 * @internal
 */
export function implicitRejectionKdk(key: KeyObject, ciphertext: Uint8Array): Buffer {
  let secret = kdkKeys.get(key);
  if (!secret) {
    const jwk = key.export({ format: "jwk" });
    if (!jwk.d || !jwk.n) throw new TypeError("Expected an RSA private key");
    const length = Buffer.from(jwk.n, "base64url").length;
    const exponent = Buffer.from(jwk.d, "base64url");
    const d = Buffer.alloc(length);
    exponent.copy(d, length - exponent.length);
    secret = { hash: nodeCrypto.createHash("sha256").update(d).digest(), length };
    kdkKeys.set(key, secret);
  }
  const c = Buffer.alloc(Math.max(secret.length, ciphertext.length));
  c.set(ciphertext, c.length - ciphertext.length);
  return nodeCrypto.createHmac("sha256", secret.hash).update(c).digest();
}

/** HMAC-SHA256 counter-mode PRF of draft-irtf-cfrg-rsa-guidance. @internal */
export function rsaPrf(kdk: Buffer, label: string, length: number): Buffer {
  const out = Buffer.alloc(length);
  const bits = Buffer.alloc(2);
  bits.writeUInt16BE((length * 8) & 0xffff);
  for (let pos = 0, i = 0; pos < length; pos += 32, i++) {
    const counter = Buffer.alloc(2);
    counter.writeUInt16BE(i);
    nodeCrypto.createHmac("sha256", kdk).update(counter).update(label).update(bits).digest().copy(out, pos);
  }
  return out;
}

// Branch-free helpers over small non-negative integers (< 2^31). Bits are 0 or 1.
const ctEq = (a: number, b: number): number => (((a ^ b) - 1) >>> 31) & 1;
const ctLt = (a: number, b: number): number => ((a - b) >>> 31) & 1;
const ctSelect = (bit: number, a: number, b: number): number => b ^ ((a ^ b) & -bit);

/**
 * Decode EM = 0x00 || 0x02 || PS || 0x00 || M (|PS| >= 8) with implicit rejection: on malformed
 * padding, return a synthetic message whose length and content are derived from `kdk`. The work
 * done does not depend on the padding.
 * @internal
 */
export function pkcs1v15DecodeImplicit(em: Uint8Array, kdk: Buffer): Buffer {
  const k = em.length;
  const maxSepOffset = k - 2 - 8;
  const candidates = rsaPrf(kdk, "length", 256);
  const synthetic = rsaPrf(kdk, "message", k);

  let lengthMask = maxSepOffset;
  lengthMask |= lengthMask >> 1;
  lengthMask |= lengthMask >> 2;
  lengthMask |= lengthMask >> 4;
  lengthMask |= lengthMask >> 8;
  let syntheticLength = 0;
  for (let i = 0; i < candidates.length; i += 2) {
    const candidate = ((candidates[i]! << 8) | candidates[i + 1]!) & lengthMask;
    syntheticLength = ctSelect(ctLt(candidate, maxSepOffset), candidate, syntheticLength);
  }

  let good = ctEq(em[0]!, 0) & ctEq(em[1]!, 2);
  let zeroIndex = 0;
  let found = 0;
  for (let i = 2; i < k; i++) {
    const isZero = ctEq(em[i]!, 0);
    zeroIndex = ctSelect(isZero & (found ^ 1), i, zeroIndex);
    found |= isZero;
  }
  good &= found & (ctLt(zeroIndex, 2 + 8) ^ 1);

  const out = Buffer.alloc(k);
  for (let i = 0; i < k; i++) out[i] = ctSelect(good, em[i]!, synthetic[i]!);
  return out.subarray(ctSelect(good, zeroIndex + 1, k - syntheticLength));
}

// ---------------------------------------------------------------------------
// Content encryption
// ---------------------------------------------------------------------------

interface CipherInfo {
  oid: string;
  keyLength: number;
  ivLength: number;
}

export const CONTENT_ENCRYPTION: Record<EncryptionAlgorithm, CipherInfo> = {
  "aes-128-cbc": { oid: OID.aes128CBC, keyLength: 16, ivLength: 16 },
  "aes-192-cbc": { oid: OID.aes192CBC, keyLength: 24, ivLength: 16 },
  "aes-256-cbc": { oid: OID.aes256CBC, keyLength: 32, ivLength: 16 },
  "des-ede3-cbc": { oid: OID.desEde3CBC, keyLength: 24, ivLength: 8 },
  "des-cbc": { oid: OID.desCBC, keyLength: 8, ivLength: 8 },
};

/**
 * OpenSSL 3 only offers single DES through its legacy provider. Triple DES in EDE mode with
 * K1 = K2 = K3 is exactly single DES, so map it onto des-ede3-cbc.
 */
function cipherParams(algorithm: EncryptionAlgorithm, key: Buffer): [string, Buffer] {
  if (algorithm === "des-cbc") return ["des-ede3-cbc", Buffer.concat([key, key, key])];
  return [algorithm, key];
}

export function encryptionAlgorithmFromOid(oid: string): EncryptionAlgorithm {
  for (const [name, info] of Object.entries(CONTENT_ENCRYPTION)) if (info.oid === oid) return name as EncryptionAlgorithm;
  throw new ScepProtocolError(`Unsupported content-encryption algorithm ${oid}`, FailInfo.badAlg);
}

export function encryptContent(
  algorithm: EncryptionAlgorithm,
  plaintext: BytesLike,
): { key: Buffer; iv: Buffer; ciphertext: Buffer } {
  const info = CONTENT_ENCRYPTION[algorithm];
  const key = nodeCrypto.randomBytes(info.keyLength);
  const iv = nodeCrypto.randomBytes(info.ivLength);
  const cipher = nodeCrypto.createCipheriv(...cipherParams(algorithm, key), iv);
  const ciphertext = Buffer.concat([cipher.update(toBuffer(plaintext)), cipher.final()]);
  return { key, iv, ciphertext };
}

export function decryptContent(algorithm: EncryptionAlgorithm, key: BytesLike, iv: BytesLike, ciphertext: BytesLike): Buffer {
  try {
    const decipher = nodeCrypto.createDecipheriv(...cipherParams(algorithm, toBuffer(key)), toBuffer(iv));
    return Buffer.concat([decipher.update(toBuffer(ciphertext)), decipher.final()]);
  } catch (err) {
    throw new ScepProtocolError("Unable to decrypt pkcsPKIEnvelope", FailInfo.badMessageCheck, { cause: err });
  }
}

export function randomBytes(length: number): Buffer {
  return nodeCrypto.randomBytes(length);
}
