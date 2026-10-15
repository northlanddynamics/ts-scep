/**
 * SCEP pkiMessage encoding and decoding (RFC 8894 §3).
 *
 * ```
 * pkiMessage = ContentInfo(SignedData {
 *   encapContentInfo: id-data, eContent = pkcsPKIEnvelope (EnvelopedData) — omitted for
 *                     CertRep with pkiStatus FAILURE or PENDING
 *   signerInfo.signedAttrs: transactionID, messageType, senderNonce, [recipientNonce],
 *                           [pkiStatus], [failInfo], [failInfoText], contentType, messageDigest
 * })
 * ```
 */
import type { KeyObject, X509Certificate } from "node:crypto";
import { IssuerAndSerialNumber } from "@peculiar/asn1-cms";
import { IssuerAndSubject, octetString, parse, printableString, readOctetString, readString, serialize, utf8String } from "./asn1.js";
import { createEnvelopedData, createSignedData, openEnvelopedData, parseSignedData, verifySignerInfo } from "./cms.js";
import {
  FailInfo,
  MessageType,
  PkiStatus,
  type DigestAlgorithm,
  type EncryptionAlgorithm,
  type KeyTransportAlgorithm,
} from "./constants.js";
import { digest, randomBytes, toPublicKey, type PublicKeyLike } from "./crypto.js";
import { ScepProtocolError } from "./errors.js";
import { OID } from "./oids.js";
import { normalizeInteger, toArrayBuffer, toBuffer, type BytesLike } from "./util.js";
import { buildName, certificateIssuer, certificateSerialNumber, type CertificateLike, type NameInput, toCertificate } from "./x509.js";

/** Size of sender/recipient nonces (RFC 8894 §3.2.1.5: 16 bytes of random data). */
export const NONCE_LENGTH = 16;

/** A certificate and its private key, used to sign SCEP messages and decrypt replies. */
export interface ScepIdentity {
  certificate: X509Certificate;
  privateKey: KeyObject;
}

export interface EncodePkiMessageOptions {
  messageType: MessageType;
  transactionId: string;
  /** 16 random bytes are generated when omitted. */
  senderNonce?: BytesLike;
  /** Required on CertRep: the senderNonce of the request being answered. */
  recipientNonce?: BytesLike;
  pkiStatus?: PkiStatus;
  failInfo?: FailInfo;
  failInfoText?: string;
  /** messageData, sent inside the pkcsPKIEnvelope encrypted for `recipient`. */
  messageData?: BytesLike;
  /** Certificate the pkcsPKIEnvelope is encrypted for. Required with `messageData`. */
  recipient?: X509Certificate;
  signer: ScepIdentity;
  digestAlgorithm?: DigestAlgorithm;
  encryptionAlgorithm?: EncryptionAlgorithm;
  /** Key-transport scheme for the pkcsPKIEnvelope (default rsa-pkcs1). */
  keyTransport?: KeyTransportAlgorithm;
  /** Additional certificates to include in the SignedData (the signer certificate is always included). */
  certificates?: X509Certificate[];
  /** signingTime attribute; defaults to now, `false` omits it. */
  signingTime?: Date | false;
}

/** Build a signed (and, where there is message data, enveloped) SCEP pkiMessage. */
export function encodePkiMessage(opts: EncodePkiMessageOptions): Buffer {
  const senderNonce = opts.senderNonce ? toBuffer(opts.senderNonce) : randomBytes(NONCE_LENGTH);
  const attrs: Array<{ type: string; values: BytesLike[] }> = [
    { type: OID.scepTransactionId, values: [printableString(opts.transactionId)] },
    { type: OID.scepMessageType, values: [printableString(String(opts.messageType))] },
    { type: OID.scepSenderNonce, values: [octetString(senderNonce)] },
  ];
  if (opts.recipientNonce) attrs.push({ type: OID.scepRecipientNonce, values: [octetString(opts.recipientNonce)] });
  if (opts.pkiStatus !== undefined) attrs.push({ type: OID.scepPkiStatus, values: [printableString(String(opts.pkiStatus))] });
  if (opts.failInfo !== undefined) attrs.push({ type: OID.scepFailInfo, values: [printableString(String(opts.failInfo))] });
  if (opts.failInfoText) attrs.push({ type: OID.scepFailInfoText, values: [utf8String(opts.failInfoText)] });

  if (opts.messageType === MessageType.CertRep) {
    if (opts.pkiStatus === undefined) throw new TypeError("CertRep requires pkiStatus");
    if (!opts.recipientNonce) throw new TypeError("CertRep requires recipientNonce");
    if (opts.pkiStatus === PkiStatus.FAILURE && opts.failInfo === undefined) {
      throw new TypeError("CertRep with pkiStatus FAILURE requires failInfo");
    }
  }

  let envelope: Buffer | undefined;
  if (opts.messageData !== undefined) {
    if (!opts.recipient) throw new TypeError("messageData requires a recipient certificate");
    envelope = createEnvelopedData(
      opts.messageData,
      opts.recipient,
      opts.encryptionAlgorithm ?? "aes-128-cbc",
      opts.keyTransport,
    );
  }

  return createSignedData({
    content: envelope,
    certificates: opts.certificates,
    signer: {
      certificate: opts.signer.certificate,
      privateKey: opts.signer.privateKey,
      digestAlgorithm: opts.digestAlgorithm ?? "sha256",
      attributes: attrs,
      signingTime: opts.signingTime,
    },
  });
}

/** A decoded and signature-verified pkiMessage. */
export interface PkiMessage {
  messageType: MessageType;
  transactionId: string;
  senderNonce: Buffer;
  recipientNonce?: Buffer;
  pkiStatus?: PkiStatus;
  failInfo?: FailInfo;
  failInfoText?: string;
  signingTime?: Date;
  /** Certificate that signed the message. */
  signerCertificate: X509Certificate;
  /** All certificates carried in the SignedData. */
  certificates: X509Certificate[];
  digestAlgorithm: DigestAlgorithm;
  /** The encrypted pkcsPKIEnvelope (ContentInfo DER), if present. */
  envelope?: Buffer;
  /** Decrypted messageData, if an envelope was present and recipient credentials were supplied. */
  messageData?: Buffer;
  /** Content-encryption algorithm of the envelope, once decrypted. */
  encryptionAlgorithm?: EncryptionAlgorithm;
  /** Key-transport scheme of the envelope, once decrypted. */
  keyTransport?: KeyTransportAlgorithm;
}

export interface DecodePkiMessageOptions {
  /** Credentials to decrypt the pkcsPKIEnvelope. Without them `messageData` is left undefined. */
  recipient?: ScepIdentity;
  /** Candidate signer certificates, for messages that do not carry their signer's certificate. */
  signerCertificates?: X509Certificate[];
}

function intAttr(values: Buffer[] | undefined, name: string): number | undefined {
  if (!values?.length) return undefined;
  const text = readString(values[0]!).trim();
  if (!/^\d+$/.test(text)) throw new ScepProtocolError(`Invalid ${name} value "${text}"`, FailInfo.badRequest);
  return Number(text);
}

/** Decode a pkiMessage, verifying its signature and (optionally) decrypting its envelope. */
export function decodePkiMessage(der: BytesLike, opts: DecodePkiMessageOptions = {}): PkiMessage {
  const sd = parseSignedData(der);
  if (sd.signerInfos.length !== 1) {
    throw new ScepProtocolError(`Expected exactly one SignerInfo, found ${sd.signerInfos.length}`, FailInfo.badMessageCheck);
  }
  if (sd.contentType !== OID.data) {
    throw new ScepProtocolError(`Unexpected encapsulated content type ${sd.contentType}`, FailInfo.badRequest);
  }
  const signer = verifySignerInfo(sd, sd.signerInfos[0]!, opts.signerCertificates);
  const a = signer.attributes;

  const messageType = intAttr(a.get(OID.scepMessageType), "messageType");
  if (messageType === undefined) throw new ScepProtocolError("Missing messageType attribute", FailInfo.badRequest);
  if (!(messageType in MessageType)) {
    throw new ScepProtocolError(`Unsupported messageType ${messageType}`, FailInfo.badRequest);
  }
  const tid = a.get(OID.scepTransactionId)?.[0];
  if (!tid) throw new ScepProtocolError("Missing transactionID attribute", FailInfo.badRequest);
  const sn = a.get(OID.scepSenderNonce)?.[0];
  if (!sn) throw new ScepProtocolError("Missing senderNonce attribute", FailInfo.badRequest);
  const rn = a.get(OID.scepRecipientNonce)?.[0];
  const fit = a.get(OID.scepFailInfoText)?.[0];

  const msg: PkiMessage = {
    messageType,
    transactionId: readString(tid),
    senderNonce: readOctetString(sn),
    recipientNonce: rn ? readOctetString(rn) : undefined,
    pkiStatus: intAttr(a.get(OID.scepPkiStatus), "pkiStatus"),
    failInfo: intAttr(a.get(OID.scepFailInfo), "failInfo"),
    failInfoText: fit ? readString(fit) : undefined,
    signingTime: signer.signingTime,
    signerCertificate: signer.certificate,
    certificates: sd.certificates,
    digestAlgorithm: signer.digestAlgorithm,
    envelope: sd.content?.length ? sd.content : undefined,
  };

  if (msg.messageType === MessageType.CertRep) {
    if (msg.pkiStatus === undefined) throw new ScepProtocolError("CertRep without pkiStatus", FailInfo.badRequest);
    if (!(msg.pkiStatus in PkiStatus)) {
      throw new ScepProtocolError(`Unknown pkiStatus ${msg.pkiStatus}`, FailInfo.badRequest);
    }
  }

  if (msg.envelope && opts.recipient) {
    const opened = openEnvelopedData(msg.envelope, opts.recipient.certificate, opts.recipient.privateKey);
    msg.messageData = opened.content;
    msg.encryptionAlgorithm = opened.algorithm;
    msg.keyTransport = opened.keyTransport;
  }
  return msg;
}

/**
 * Read the SCEP attributes of a message without verifying it. Useful for a server that
 * must reply with a FAILURE CertRep to a message whose signature does not verify.
 */
export function peekPkiMessage(
  der: BytesLike,
): { messageType?: number; transactionId?: string; senderNonce?: Buffer; signerCertificate?: X509Certificate } | undefined {
  try {
    const sd = parseSignedData(der);
    const si = sd.signerInfos[0];
    if (!si?.signedAttrs) return undefined;
    const get = (oid: string) => {
      const v = si.signedAttrs!.find((x) => x.attrType === oid)?.attrValues[0];
      return v ? toBuffer(v) : undefined;
    };
    const tid = get(OID.scepTransactionId);
    const sn = get(OID.scepSenderNonce);
    const mt = get(OID.scepMessageType);
    return {
      messageType: mt ? Number(readString(mt)) : undefined,
      transactionId: tid ? readString(tid) : undefined,
      senderNonce: sn ? readOctetString(sn) : undefined,
      signerCertificate: sd.certificates[0],
    };
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// messageData structures (RFC 8894 §3.3)
// ---------------------------------------------------------------------------

/** IssuerAndSerialNumber — messageData of GetCert and GetCRL. */
export function encodeIssuerAndSerialNumber(issuer: NameInput, serialNumber: BytesLike): Buffer {
  const serial = normalizeInteger(serialNumber);
  const padded = serial[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), serial]) : serial;
  return serialize(new IssuerAndSerialNumber({ issuer: buildName(issuer), serialNumber: toArrayBuffer(padded) }));
}

/** IssuerAndSerialNumber identifying an existing certificate. */
export function issuerAndSerialNumberOfCertificate(cert: CertificateLike): Buffer {
  const c = toCertificate(cert);
  return encodeIssuerAndSerialNumber(certificateIssuer(c), certificateSerialNumber(c));
}

export function decodeIssuerAndSerialNumber(der: BytesLike): { issuer: Buffer; serialNumber: Buffer } {
  const ias = parse(der, IssuerAndSerialNumber, "IssuerAndSerialNumber");
  return { issuer: serialize(ias.issuer), serialNumber: normalizeInteger(ias.serialNumber) };
}

/** IssuerAndSubject — messageData of CertPoll. */
export function encodeIssuerAndSubject(issuer: NameInput, subject: NameInput): Buffer {
  return serialize(new IssuerAndSubject({ issuer: buildName(issuer), subject: buildName(subject) }));
}

export function decodeIssuerAndSubject(der: BytesLike): { issuer: Buffer; subject: Buffer } {
  const ias = parse(der, IssuerAndSubject, "IssuerAndSubject");
  return { issuer: serialize(ias.issuer), subject: serialize(ias.subject) };
}

/**
 * Derive a transactionID from a public key: upper-case hex SHA-256 of the SubjectPublicKeyInfo.
 * Deterministic IDs let a client resume a transaction after a restart. Any unique
 * PrintableString is acceptable (RFC 8894 §3.2.1.1).
 */
export function transactionIdFromPublicKey(key: PublicKeyLike): string {
  const spki = toPublicKey(key).export({ type: "spki", format: "der" });
  return digest("sha256", spki).toString("hex").toUpperCase();
}

/** A random transactionID (32 hex characters). */
export function randomTransactionId(): string {
  return randomBytes(16).toString("hex").toUpperCase();
}
