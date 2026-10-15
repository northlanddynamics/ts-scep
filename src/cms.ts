/**
 * The subset of CMS (RFC 5652) that SCEP uses: SignedData with signed attributes, degenerate
 * certificates-only SignedData, and EnvelopedData with RSA key transport.
 */
import type { KeyObject, X509Certificate } from "node:crypto";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import * as cms from "@peculiar/asn1-cms";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { AnySet, OaepParams, ScepSignedData, objectIdentifier, octetString, readObjectIdentifier, parse, readOctetString, serialize, sortDerSet } from "./asn1.js";
import type { DigestAlgorithm, EncryptionAlgorithm, KeyTransportAlgorithm } from "./constants.js";
import { FailInfo } from "./constants.js";
import {
  CONTENT_ENCRYPTION,
  DIGEST_OIDS,
  decryptContent,
  digest,
  digestAlgorithmFromOid,
  encryptContent,
  encryptionAlgorithmFromOid,
  resolveKeyTransport,
  rsaDecrypt,
  rsaEncrypt,
  type ResolvedKeyTransport,
  sign,
  signatureDigest,
  verify,
} from "./crypto.js";
import { ScepProtocolError } from "./errors.js";
import { OID } from "./oids.js";
import { bytesEqual, normalizeInteger, toArrayBuffer, toBuffer, type BytesLike } from "./util.js";
import { certificateSubjectKeyIdentifier, parseCertificateAsn, toCertificate } from "./x509.js";

// ---------------------------------------------------------------------------
// ContentInfo
// ---------------------------------------------------------------------------

export function encodeContentInfo(contentType: string, content: BytesLike): Buffer {
  return serialize(new cms.ContentInfo({ contentType, content: toArrayBuffer(content) }));
}

export function decodeContentInfo(der: BytesLike, expectedType?: string): { contentType: string; content: Buffer } {
  const ci = parse(der, cms.ContentInfo, "CMS ContentInfo");
  if (expectedType && ci.contentType !== expectedType) {
    throw new ScepProtocolError(`Unexpected CMS content type ${ci.contentType}`, FailInfo.badRequest);
  }
  return { contentType: ci.contentType, content: toBuffer(ci.content) };
}

// ---------------------------------------------------------------------------
// Signer identification
// ---------------------------------------------------------------------------

function issuerAndSerialNumberOf(cert: X509Certificate): cms.IssuerAndSerialNumber {
  const tbs = parseCertificateAsn(cert).tbsCertificate;
  return new cms.IssuerAndSerialNumber({ issuer: tbs.issuer, serialNumber: tbs.serialNumber });
}

function matchesIssuerAndSerial(cert: X509Certificate, ias: cms.IssuerAndSerialNumber): boolean {
  const tbs = parseCertificateAsn(cert).tbsCertificate;
  return (
    bytesEqual(normalizeInteger(tbs.serialNumber), normalizeInteger(ias.serialNumber)) &&
    bytesEqual(serialize(tbs.issuer), serialize(ias.issuer))
  );
}

function matchesIdentifier(
  cert: X509Certificate,
  id: { issuerAndSerialNumber?: cms.IssuerAndSerialNumber; subjectKeyIdentifier?: { buffer: ArrayBuffer } },
): boolean {
  if (id.issuerAndSerialNumber) return matchesIssuerAndSerial(cert, id.issuerAndSerialNumber);
  if (id.subjectKeyIdentifier) {
    const ski = certificateSubjectKeyIdentifier(cert);
    return !!ski && bytesEqual(ski, id.subjectKeyIdentifier.buffer);
  }
  return false;
}

// ---------------------------------------------------------------------------
// SignedData
// ---------------------------------------------------------------------------

export interface Signer {
  certificate: X509Certificate;
  privateKey: KeyObject;
  digestAlgorithm: DigestAlgorithm;
  /** Additional signed attributes (type OID → DER-encoded values). */
  attributes?: Array<{ type: string; values: BytesLike[] }>;
  /** Include a signingTime attribute. Defaults to the current time; `false` omits it. */
  signingTime?: Date | false;
}

export interface CreateSignedDataOptions {
  /** Encapsulated content (eContentType id-data). Omitted for degenerate or content-less SignedData. */
  content?: BytesLike;
  signer?: Signer;
  certificates?: X509Certificate[];
  /** DER-encoded CRLs. */
  crls?: BytesLike[];
}

function attribute(type: string, values: BytesLike[]): cms.Attribute {
  return new cms.Attribute({ attrType: type, attrValues: values.map((v) => toArrayBuffer(v)) });
}

function algorithmIdentifier(algorithm: string, nullParams = true): AlgorithmIdentifier {
  return new AlgorithmIdentifier({ algorithm, parameters: nullParams ? null : undefined });
}

/** Build a CMS ContentInfo wrapping SignedData. */
export function createSignedData(opts: CreateSignedDataOptions): Buffer {
  const content = opts.content !== undefined ? toBuffer(opts.content) : undefined;
  const sd = new ScepSignedData({
    version: 1,
    encapContentInfo: new cms.EncapsulatedContentInfo({
      eContentType: OID.data,
      eContent: content ? new cms.EncapsulatedContent({ single: new OctetString(toArrayBuffer(content)) }) : undefined,
    }),
  });

  const certs = [...(opts.certificates ?? [])];
  if (opts.signer && !certs.some((c) => c.raw.equals(opts.signer!.certificate.raw))) {
    certs.unshift(opts.signer.certificate);
  }
  if (certs.length) sd.certificates = new AnySet(certs.map((c) => toArrayBuffer(c.raw)));
  if (opts.crls?.length) sd.crls = new AnySet(opts.crls.map((c) => toArrayBuffer(c)));

  if (opts.signer) {
    const { certificate, privateKey, digestAlgorithm } = opts.signer;
    const digestAlg = algorithmIdentifier(DIGEST_OIDS[digestAlgorithm]);
    sd.digestAlgorithms = new cms.DigestAlgorithmIdentifiers([digestAlg]);

    const attrs: cms.Attribute[] = [
      attribute(OID.contentType, [objectIdentifier(OID.data)]),
      attribute(OID.messageDigest, [octetString(digest(digestAlgorithm, content ?? Buffer.alloc(0)))]),
    ];
    if (opts.signer.signingTime !== false) {
      const time = new cms.SigningTime(opts.signer.signingTime ?? new Date());
      attrs.push(attribute(OID.signingTime, [AsnConvert.serialize(time)]));
    }
    for (const a of opts.signer.attributes ?? []) attrs.push(attribute(a.type, a.values));
    const sortedAttrs = sortDerSet(attrs, (a) => AsnConvert.serialize(a));

    // The signature covers the DER encoding of the attributes with an explicit SET OF tag.
    const signedAttrsDer = Buffer.concat(sortedAttrs.map((a) => serialize(a)));
    const toSign = Buffer.concat([Buffer.from([0x31]), derLength(signedAttrsDer.length), signedAttrsDer]);

    const signerInfo = new cms.SignerInfo({
      version: cms.CMSVersion.v1,
      sid: new cms.SignerIdentifier({ issuerAndSerialNumber: issuerAndSerialNumberOf(certificate) }),
      digestAlgorithm: digestAlg,
      signedAttrs: sortedAttrs,
      signatureAlgorithm: algorithmIdentifier(
        privateKey.asymmetricKeyType === "rsa" ? OID.rsaEncryption : ecdsaOid(digestAlgorithm),
        privateKey.asymmetricKeyType === "rsa",
      ),
      signature: new OctetString(toArrayBuffer(sign(digestAlgorithm, privateKey, toSign))),
    });
    sd.signerInfos = new cms.SignerInfos([signerInfo]);
  }

  return encodeContentInfo(OID.signedData, serialize(sd));
}

function ecdsaOid(alg: DigestAlgorithm): string {
  return { sha1: "1.2.840.10045.4.1", sha256: "1.2.840.10045.4.3.2", sha384: "1.2.840.10045.4.3.3", sha512: "1.2.840.10045.4.3.4" }[alg];
}

function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  for (let l = length; l > 0; l >>= 8) bytes.unshift(l & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** A certificates-only ("degenerate") SignedData carrying certificates and/or CRLs (RFC 8894 §3.4). */
export function createDegenerateSignedData(certificates: X509Certificate[], crls: BytesLike[] = []): Buffer {
  return createSignedData({ certificates, crls });
}

export interface ParsedSignedData {
  /** eContentType of the encapsulated content. */
  contentType: string;
  /** Encapsulated content, if present. */
  content?: Buffer;
  certificates: X509Certificate[];
  /** DER-encoded CRLs. */
  crls: Buffer[];
  signerInfos: cms.SignerInfo[];
  asn: ScepSignedData;
}

/** Parse a ContentInfo carrying SignedData. Signatures are not checked; see {@link verifySignerInfo}. */
export function parseSignedData(der: BytesLike): ParsedSignedData {
  const { content } = decodeContentInfo(der, OID.signedData);
  const sd = parse(content, ScepSignedData, "CMS SignedData");
  const certificates: X509Certificate[] = [];
  for (const raw of sd.certificates ?? []) {
    // Only plain X.509 certificates (universal SEQUENCE tag) are of interest to SCEP.
    if (new Uint8Array(raw)[0] !== 0x30) continue;
    certificates.push(toCertificate(new Uint8Array(raw)));
  }
  const crls = [...(sd.crls ?? [])]
    .filter((raw) => new Uint8Array(raw)[0] === 0x30)
    .map((raw) => toBuffer(raw));
  let econtent: Buffer | undefined;
  const ec = sd.encapContentInfo.eContent;
  if (ec?.single) econtent = toBuffer(ec.single.buffer);
  else if (ec?.any) econtent = readOctetString(ec.any);
  return {
    contentType: sd.encapContentInfo.eContentType,
    content: econtent,
    certificates,
    crls,
    signerInfos: [...sd.signerInfos],
    asn: sd,
  };
}

export interface VerifiedSigner {
  certificate: X509Certificate;
  digestAlgorithm: DigestAlgorithm;
  /** Signed attributes: OID → list of DER-encoded values. */
  attributes: Map<string, Buffer[]>;
  signingTime?: Date;
}

/**
 * Verify a SignerInfo: locate the signer certificate (in the SignedData or among
 * `candidates`), check the messageDigest and contentType attributes and the signature.
 */
export function verifySignerInfo(
  sd: ParsedSignedData,
  signerInfo: cms.SignerInfo,
  candidates: X509Certificate[] = [],
): VerifiedSigner {
  const pool = [...candidates, ...sd.certificates];
  const certificate = pool.find((c) => matchesIdentifier(c, signerInfo.sid));
  if (!certificate) {
    throw new ScepProtocolError("Signer certificate not found", FailInfo.badCertId);
  }
  const digestAlgorithm = digestAlgorithmFromOid(signerInfo.digestAlgorithm.algorithm);
  if (!signerInfo.signedAttrs?.length) {
    throw new ScepProtocolError("SignerInfo has no signed attributes", FailInfo.badMessageCheck);
  }

  const attributes = new Map<string, Buffer[]>();
  for (const a of signerInfo.signedAttrs) {
    attributes.set(a.attrType, [...(attributes.get(a.attrType) ?? []), ...a.attrValues.map((v) => toBuffer(v))]);
  }

  const md = attributes.get(OID.messageDigest)?.[0];
  if (!md) throw new ScepProtocolError("Missing messageDigest attribute", FailInfo.badMessageCheck);
  if (!readOctetString(md).equals(digest(digestAlgorithm, sd.content ?? Buffer.alloc(0)))) {
    throw new ScepProtocolError("messageDigest does not match content", FailInfo.badMessageCheck);
  }
  const ct = attributes.get(OID.contentType)?.[0];
  if (ct) {
    const type = readObjectIdentifier(ct);
    if (type !== sd.contentType) throw new ScepProtocolError("contentType attribute mismatch", FailInfo.badMessageCheck);
  }

  let signedAttrsDer: Buffer;
  if (signerInfo.signedAttrsRaw) {
    signedAttrsDer = Buffer.from(toBuffer(signerInfo.signedAttrsRaw));
    signedAttrsDer[0] = 0x31; // [0] IMPLICIT -> SET OF
  } else {
    const body = Buffer.concat(signerInfo.signedAttrs.map((a) => serialize(a)));
    signedAttrsDer = Buffer.concat([Buffer.from([0x31]), derLength(body.length), body]);
  }
  const sigDigest = signatureDigest(signerInfo.signatureAlgorithm.algorithm, digestAlgorithm);
  if (!verify(sigDigest, certificate.publicKey, signedAttrsDer, signerInfo.signature.buffer)) {
    throw new ScepProtocolError("Signature verification failed", FailInfo.badMessageCheck);
  }

  let signingTime: Date | undefined;
  const st = attributes.get(OID.signingTime)?.[0];
  if (st) signingTime = AsnConvert.parse(st, cms.SigningTime).getTime();

  return { certificate, digestAlgorithm, attributes, signingTime };
}

// ---------------------------------------------------------------------------
// EnvelopedData
// ---------------------------------------------------------------------------

/**
 * Hash AlgorithmIdentifier inside RSAES-OAEP-params. SHA-1 keeps NULL parameters to match the
 * ASN.1 DEFAULT value (so it is omitted under DER); other hashes omit them (RFC 4055 §2.1).
 */
function oaepHashIdentifier(hash: DigestAlgorithm): AlgorithmIdentifier {
  return algorithmIdentifier(DIGEST_OIDS[hash], hash === "sha1");
}

/** keyEncryptionAlgorithm for a KeyTransRecipientInfo. */
function keyEncryptionAlgorithmIdentifier(kt: ResolvedKeyTransport): AlgorithmIdentifier {
  if (kt.scheme === "rsa-pkcs1") return algorithmIdentifier(OID.rsaEncryption);
  const params = new OaepParams();
  if (kt.hash !== "sha1") {
    params.hashAlgorithm = oaepHashIdentifier(kt.hash);
    params.maskGenAlgorithm = new AlgorithmIdentifier({ algorithm: OID.mgf1, parameters: AsnConvert.serialize(oaepHashIdentifier(kt.hash)) });
  }
  if (kt.label.length) {
    params.pSourceAlgorithm = new AlgorithmIdentifier({ algorithm: OID.pSpecified, parameters: octetString(kt.label) });
  }
  return new AlgorithmIdentifier({ algorithm: OID.rsaesOaep, parameters: AsnConvert.serialize(params) });
}

function oaepHashFromIdentifier(id: AlgorithmIdentifier): DigestAlgorithm {
  const hash = (Object.keys(DIGEST_OIDS) as DigestAlgorithm[]).find((h) => DIGEST_OIDS[h] === id.algorithm);
  if (!hash) throw new ScepProtocolError(`Unsupported RSA-OAEP hash algorithm ${id.algorithm}`, FailInfo.badAlg);
  // Parameters must be absent or NULL; implementations differ on which (RFC 4055 §2.1).
  if (id.parameters && !bytesEqual(toBuffer(id.parameters), Buffer.from([0x05, 0x00]))) {
    throw new ScepProtocolError("Unexpected hash algorithm parameters in RSA-OAEP parameters", FailInfo.badAlg);
  }
  return hash;
}

/** Interpret a KeyTransRecipientInfo keyEncryptionAlgorithm. */
function keyTransportFromIdentifier(id: AlgorithmIdentifier): ResolvedKeyTransport {
  if (id.algorithm === OID.rsaEncryption) return { scheme: "rsa-pkcs1" };
  if (id.algorithm !== OID.rsaesOaep) {
    throw new ScepProtocolError(`Unsupported key encryption algorithm ${id.algorithm}`, FailInfo.badAlg);
  }
  const params = id.parameters ? parse(id.parameters, OaepParams, "RSAES-OAEP parameters") : new OaepParams();
  const hash = params.hashAlgorithm ? oaepHashFromIdentifier(params.hashAlgorithm) : "sha1";

  let mgfHash: DigestAlgorithm = "sha1";
  if (params.maskGenAlgorithm) {
    if (params.maskGenAlgorithm.algorithm !== OID.mgf1 || !params.maskGenAlgorithm.parameters) {
      throw new ScepProtocolError(`Unsupported RSA-OAEP mask generation function ${params.maskGenAlgorithm.algorithm}`, FailInfo.badAlg);
    }
    mgfHash = oaepHashFromIdentifier(parse(params.maskGenAlgorithm.parameters, AlgorithmIdentifier, "MGF1 parameters"));
  }
  // Node.js (OpenSSL's EVP_PKEY_CTX_set_rsa_oaep_md) always uses the OAEP hash for MGF1.
  if (mgfHash !== hash) {
    throw new ScepProtocolError(`RSA-OAEP with ${hash} and MGF1-${mgfHash} is not supported`, FailInfo.badAlg);
  }

  let label: Buffer = Buffer.alloc(0);
  if (params.pSourceAlgorithm) {
    if (params.pSourceAlgorithm.algorithm !== OID.pSpecified || !params.pSourceAlgorithm.parameters) {
      throw new ScepProtocolError(`Unsupported RSA-OAEP label source ${params.pSourceAlgorithm.algorithm}`, FailInfo.badAlg);
    }
    label = readOctetString(params.pSourceAlgorithm.parameters);
  }
  return { scheme: "rsa-oaep", hash, label };
}

/** Express a resolved key-transport scheme in its public form. */
function publicKeyTransport(kt: ResolvedKeyTransport): KeyTransportAlgorithm {
  if (kt.scheme === "rsa-pkcs1") return "rsa-pkcs1";
  return kt.label.length ? { scheme: "rsa-oaep", hash: kt.hash, label: kt.label } : { scheme: "rsa-oaep", hash: kt.hash };
}

/** Encrypt `content` for `recipient` (RSA key transport) and wrap it in a ContentInfo. */
export function createEnvelopedData(
  content: BytesLike,
  recipient: X509Certificate,
  algorithm: EncryptionAlgorithm,
  keyTransport: KeyTransportAlgorithm = "rsa-pkcs1",
): Buffer {
  const kt = resolveKeyTransport(keyTransport);
  const { key, iv, ciphertext } = encryptContent(algorithm, content);
  const ktri = new cms.KeyTransRecipientInfo({
    version: cms.CMSVersion.v0,
    rid: new cms.RecipientIdentifier({ issuerAndSerialNumber: issuerAndSerialNumberOf(recipient) }),
    keyEncryptionAlgorithm: keyEncryptionAlgorithmIdentifier(kt),
    encryptedKey: new OctetString(toArrayBuffer(rsaEncrypt(recipient.publicKey, key, kt))),
  });
  const ed = new cms.EnvelopedData({
    version: cms.CMSVersion.v0,
    recipientInfos: new cms.RecipientInfos([new cms.RecipientInfo({ ktri })]),
    encryptedContentInfo: new cms.EncryptedContentInfo({
      contentType: OID.data,
      contentEncryptionAlgorithm: new cms.ContentEncryptionAlgorithmIdentifier({
        algorithm: CONTENT_ENCRYPTION[algorithm].oid,
        parameters: octetString(iv),
      }),
      encryptedContent: new cms.EncryptedContent({ value: new OctetString(toArrayBuffer(ciphertext)) }),
    }),
  });
  return encodeContentInfo(OID.envelopedData, serialize(ed));
}

export interface OpenedEnvelope {
  content: Buffer;
  algorithm: EncryptionAlgorithm;
  /** Key-transport scheme the sender used for the content-encryption key. */
  keyTransport: KeyTransportAlgorithm;
}

/** Decrypt a ContentInfo carrying EnvelopedData using the recipient's certificate and key. */
export function openEnvelopedData(der: BytesLike, certificate: X509Certificate, privateKey: KeyObject): OpenedEnvelope {
  const { content } = decodeContentInfo(der, OID.envelopedData);
  const ed = parse(content, cms.EnvelopedData, "CMS EnvelopedData");
  const ktris = ed.recipientInfos.map((ri) => ri.ktri).filter((k): k is cms.KeyTransRecipientInfo => !!k);
  const ktri = ktris.find((k) => matchesIdentifier(certificate, k.rid)) ?? (ktris.length === 1 ? ktris[0] : undefined);
  if (!ktri) throw new ScepProtocolError("No matching key transport recipient", FailInfo.badCertId);
  const kt = keyTransportFromIdentifier(ktri.keyEncryptionAlgorithm);

  const eci = ed.encryptedContentInfo;
  const algorithm = encryptionAlgorithmFromOid(eci.contentEncryptionAlgorithm.algorithm);
  const params = eci.contentEncryptionAlgorithm.parameters;
  if (!params) throw new ScepProtocolError("Missing content-encryption IV", FailInfo.badAlg);
  const iv = readOctetString(params);

  let ciphertext: Buffer;
  if (eci.encryptedContent?.value) ciphertext = toBuffer(eci.encryptedContent.value.buffer);
  else if (eci.encryptedContent?.constructedValue) {
    ciphertext = Buffer.concat(eci.encryptedContent.constructedValue.map((o) => toBuffer(o.buffer)));
  } else throw new ScepProtocolError("EnvelopedData has no encrypted content", FailInfo.badRequest);

  const key = rsaDecrypt(privateKey, ktri.encryptedKey.buffer, CONTENT_ENCRYPTION[algorithm].keyLength, kt);
  return { content: decryptContent(algorithm, key, iv, ciphertext), algorithm, keyTransport: publicKeyTransport(kt) };
}
