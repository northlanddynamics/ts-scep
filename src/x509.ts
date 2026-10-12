/**
 * X.509 helpers: distinguished names, certificates, PKCS #10 requests and CRLs.
 * Certificates are exposed as Node.js `X509Certificate` objects.
 */
import { X509Certificate, type KeyObject } from "node:crypto";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import * as x509 from "@peculiar/asn1-x509";
import { CertificationRequest, CertificationRequestInfo } from "@peculiar/asn1-csr";
import { ChallengePassword, ExtensionRequest } from "@peculiar/asn1-pkcs9";
import type { DigestAlgorithm } from "./constants.js";
import {
  digest,
  digestAlgorithmFromOid,
  randomBytes,
  sign,
  signatureAlgorithmOid,
  toPrivateKey,
  toPublicKey,
  verify,
  type PrivateKeyLike,
  type PublicKeyLike,
} from "./crypto.js";
import { ScepProtocolError } from "./errors.js";
import { OID } from "./oids.js";
import { parse, serialize } from "./asn1.js";
import { normalizeInteger, pemToDerList, toArrayBuffer, toBuffer, type BytesLike } from "./util.js";

/** Certificates may be given as `X509Certificate`, PEM text or DER bytes. */
export type CertificateLike = X509Certificate | string | Uint8Array;

export function toCertificate(cert: CertificateLike): X509Certificate {
  if (cert instanceof X509Certificate) return cert;
  return new X509Certificate(typeof cert === "string" ? cert : toBuffer(cert));
}

/** Parse one or more certificates from PEM text or a single DER certificate. */
export function parseCertificates(input: string | Uint8Array): X509Certificate[] {
  if (typeof input === "string") return pemToDerList(input, "CERTIFICATE").map((der) => new X509Certificate(der));
  return [new X509Certificate(toBuffer(input))];
}

// ---------------------------------------------------------------------------
// Distinguished names
// ---------------------------------------------------------------------------

const NAME_ATTRIBUTES: Record<string, string> = {
  CN: "2.5.4.3",
  SN: "2.5.4.4",
  SERIALNUMBER: "2.5.4.5",
  C: "2.5.4.6",
  L: "2.5.4.7",
  ST: "2.5.4.8",
  S: "2.5.4.8",
  STREET: "2.5.4.9",
  O: "2.5.4.10",
  OU: "2.5.4.11",
  T: "2.5.4.12",
  TITLE: "2.5.4.12",
  GN: "2.5.4.42",
  GIVENNAME: "2.5.4.42",
  INITIALS: "2.5.4.43",
  DNQUALIFIER: "2.5.4.46",
  DC: "0.9.2342.19200300.100.1.25",
  UID: "0.9.2342.19200300.100.1.1",
  E: OID.emailAddress,
  EMAIL: OID.emailAddress,
  EMAILADDRESS: OID.emailAddress,
};

const SHORT_NAMES: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.4": "SN",
  "2.5.4.5": "serialNumber",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.9": "street",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "2.5.4.12": "title",
  "2.5.4.42": "GN",
  "2.5.4.43": "initials",
  "2.5.4.46": "dnQualifier",
  "0.9.2342.19200300.100.1.25": "DC",
  "0.9.2342.19200300.100.1.1": "UID",
  [OID.emailAddress]: "emailAddress",
};

const PRINTABLE_ATTRS = new Set(["2.5.4.6", "2.5.4.5", "2.5.4.46"]);
const IA5_ATTRS = new Set(["0.9.2342.19200300.100.1.25", OID.emailAddress]);

/**
 * A distinguished name. Accepts:
 * - an RFC 4514 string (`"CN=device-1,O=Example,C=US"`, most-specific RDN first),
 * - an OpenSSL-style string (`"/C=US/O=Example/CN=device-1"`, encoding order),
 * - an array of `[type, value]` pairs in encoding order (type may be a short name or an OID),
 * - a DER-encoded Name, or an already-built asn1-x509 `Name`.
 */
export type NameInput = string | Array<[string, string]> | Uint8Array | x509.Name;

function attributeTypeOid(type: string): string {
  if (/^\d+(\.\d+)+$/.test(type)) return type;
  const oid = NAME_ATTRIBUTES[type.toUpperCase()];
  if (!oid) throw new TypeError(`Unknown distinguished name attribute "${type}"`);
  return oid;
}

function attributeValue(oid: string, value: string): x509.AttributeValue {
  if (PRINTABLE_ATTRS.has(oid)) return new x509.AttributeValue({ printableString: value });
  if (IA5_ATTRS.has(oid)) return new x509.AttributeValue({ ia5String: value });
  return new x509.AttributeValue({ utf8String: value });
}

function splitUnescaped(input: string, sep: string): string[] {
  const parts: string[] = [];
  let current = "";
  for (let i = 0; i < input.length; i++) {
    const ch = input[i]!;
    if (ch === "\\" && i + 1 < input.length) {
      current += ch + input[i + 1];
      i++;
    } else if (ch === sep) {
      parts.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  parts.push(current);
  return parts;
}

function unescapeDn(value: string): string {
  return value.replace(/\\([0-9a-fA-F]{2}|.)/g, (_, e: string) =>
    e.length === 2 ? String.fromCharCode(parseInt(e, 16)) : e,
  );
}

function parseRdn(rdn: string): x509.RelativeDistinguishedName {
  const avas = splitUnescaped(rdn, "+").map((ava) => {
    const eq = ava.indexOf("=");
    if (eq < 1) throw new TypeError(`Invalid RDN component "${ava}"`);
    const oid = attributeTypeOid(ava.slice(0, eq).trim());
    const value = unescapeDn(ava.slice(eq + 1).trim());
    return new x509.AttributeTypeAndValue({ type: oid, value: attributeValue(oid, value) });
  });
  return new x509.RelativeDistinguishedName(avas);
}

export function buildName(input: NameInput): x509.Name {
  if (input instanceof x509.Name) return input;
  if (input instanceof Uint8Array) return parse(input, x509.Name, "Name");
  if (Array.isArray(input)) {
    return new x509.Name(
      input.map(([type, value]) => {
        const oid = attributeTypeOid(type);
        return new x509.RelativeDistinguishedName([
          new x509.AttributeTypeAndValue({ type: oid, value: attributeValue(oid, value) }),
        ]);
      }),
    );
  }
  const text = input.trim();
  if (text === "") return new x509.Name();
  if (text.startsWith("/")) {
    return new x509.Name(
      splitUnescaped(text.slice(1), "/")
        .filter((p) => p.length > 0)
        .map(parseRdn),
    );
  }
  return new x509.Name(splitUnescaped(text, ",").map(parseRdn).reverse());
}

/** DER encoding of a distinguished name. */
export function encodeName(input: NameInput): Buffer {
  return serialize(buildName(input));
}

function escapeDnValue(value: string): string {
  return value.replace(/([,+"\\<>;=])/g, "\\$1").replace(/^([ #])/, "\\$1").replace(/ $/, "\\ ");
}

/** Render a Name as an RFC 4514 string (most-specific RDN first). */
export function nameToString(input: NameInput): string {
  const name = buildName(input);
  return [...name]
    .reverse()
    .map((rdn) =>
      [...rdn].map((ava) => `${SHORT_NAMES[ava.type] ?? ava.type}=${escapeDnValue(ava.value.toString())}`).join("+"),
    )
    .join(",");
}

// ---------------------------------------------------------------------------
// Certificate parsing helpers
// ---------------------------------------------------------------------------

export function parseCertificateAsn(cert: CertificateLike): x509.Certificate {
  return parse(toCertificate(cert).raw, x509.Certificate, "certificate");
}

/** DER issuer Name of a certificate. */
export function certificateIssuer(cert: CertificateLike): Buffer {
  return serialize(parseCertificateAsn(cert).tbsCertificate.issuer);
}

/** DER subject Name of a certificate. */
export function certificateSubject(cert: CertificateLike): Buffer {
  return serialize(parseCertificateAsn(cert).tbsCertificate.subject);
}

/** Serial number bytes (as encoded, possibly with a leading zero). */
export function certificateSerialNumber(cert: CertificateLike): Buffer {
  return toBuffer(parseCertificateAsn(cert).tbsCertificate.serialNumber);
}

export function certificateSubjectKeyIdentifier(cert: CertificateLike): Buffer | undefined {
  const ext = parseCertificateAsn(cert).tbsCertificate.extensions?.find((e) => e.extnID === OID.subjectKeyIdentifier);
  if (!ext) return undefined;
  return toBuffer(AsnConvert.parse(ext.extnValue, x509.SubjectKeyIdentifier).buffer);
}

export function certificateKeyUsage(cert: CertificateLike): number | undefined {
  const ext = parseCertificateAsn(cert).tbsCertificate.extensions?.find((e) => e.extnID === OID.keyUsage);
  if (!ext) return undefined;
  return AsnConvert.parse(ext.extnValue, x509.KeyUsage).toNumber();
}

/** True if the certificate's subject equals its issuer and it verifies with its own key. */
export function isSelfSigned(cert: CertificateLike): boolean {
  const c = toCertificate(cert);
  // Not X509Certificate.checkIssued(): OpenSSL also requires keyCertSign, which SCEP's
  // self-signed requester certificates normally lack.
  const tbs = parseCertificateAsn(c).tbsCertificate;
  return serialize(tbs.subject).equals(serialize(tbs.issuer)) && c.verify(c.publicKey);
}

/** True if `cert` was issued (and signed) by `issuer`. */
export function isIssuedBy(cert: CertificateLike, issuer: CertificateLike): boolean {
  const c = toCertificate(cert);
  const i = toCertificate(issuer);
  return c.checkIssued(i) && c.verify(i.publicKey);
}

export function sameCertificate(a: CertificateLike, b: CertificateLike): boolean {
  return toCertificate(a).raw.equals(toCertificate(b).raw);
}

export function samePublicKey(a: PublicKeyLike, b: PublicKeyLike): boolean {
  const da = toPublicKey(a).export({ type: "spki", format: "der" });
  const db = toPublicKey(b).export({ type: "spki", format: "der" });
  return da.equals(db);
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

export interface SubjectAltNames {
  dns?: string[];
  email?: string[];
  uri?: string[];
  ip?: string[];
  /** Raw GeneralName objects for anything else (e.g. otherName UPNs). */
  other?: x509.GeneralName[];
}

export type KeyUsageName = keyof typeof x509.KeyUsageFlags;

/** Extension options shared by certificate and CSR builders. */
export interface ExtensionOptions {
  subjectAltNames?: SubjectAltNames;
  keyUsage?: KeyUsageName[];
  /** Extended key usage OIDs, e.g. `"1.3.6.1.5.5.7.3.2"` (clientAuth). */
  extendedKeyUsage?: string[];
  /** Additional pre-built extensions. */
  extensions?: x509.Extension[];
}

function buildSubjectAltNames(san: SubjectAltNames): x509.SubjectAlternativeName {
  const names: x509.GeneralName[] = [
    ...(san.dns ?? []).map((dNSName) => new x509.GeneralName({ dNSName })),
    ...(san.email ?? []).map((rfc822Name) => new x509.GeneralName({ rfc822Name })),
    ...(san.uri ?? []).map((uniformResourceIdentifier) => new x509.GeneralName({ uniformResourceIdentifier })),
    ...(san.ip ?? []).map((iPAddress) => new x509.GeneralName({ iPAddress })),
    ...(san.other ?? []),
  ];
  return new x509.SubjectAlternativeName(names);
}

function makeExtension(extnID: string, value: unknown, critical = false): x509.Extension {
  return new x509.Extension({ extnID, critical, extnValue: new OctetString(AsnConvert.serialize(value)) });
}

function buildExtensions(opts: ExtensionOptions): x509.Extension[] {
  const exts: x509.Extension[] = [];
  if (opts.subjectAltNames) exts.push(makeExtension(OID.subjectAltName, buildSubjectAltNames(opts.subjectAltNames)));
  if (opts.keyUsage?.length) {
    const flags = opts.keyUsage.reduce((acc, k) => acc | x509.KeyUsageFlags[k], 0);
    exts.push(makeExtension(OID.keyUsage, new x509.KeyUsage(flags), true));
  }
  if (opts.extendedKeyUsage?.length) {
    exts.push(makeExtension(OID.extKeyUsage, new x509.ExtendedKeyUsage(opts.extendedKeyUsage)));
  }
  exts.push(...(opts.extensions ?? []));
  return exts;
}

function spkiOf(key: PublicKeyLike): x509.SubjectPublicKeyInfo {
  const der = toPublicKey(key).export({ type: "spki", format: "der" });
  return parse(der, x509.SubjectPublicKeyInfo, "SubjectPublicKeyInfo");
}

function keyIdentifier(key: PublicKeyLike): Buffer {
  // RFC 5280 §4.2.1.2 method 1: SHA-1 of the subjectPublicKey BIT STRING contents.
  return digest("sha1", spkiOf(key).subjectPublicKey);
}

function signatureAlgorithm(key: KeyObject, digestAlg: DigestAlgorithm): x509.AlgorithmIdentifier {
  const algorithm = signatureAlgorithmOid(key, digestAlg);
  // RSA signature algorithms carry explicit NULL parameters; ECDSA ones carry none.
  return new x509.AlgorithmIdentifier({
    algorithm,
    parameters: key.asymmetricKeyType === "rsa" ? null : undefined,
  });
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

export interface CreateCertificateOptions extends ExtensionOptions {
  subject: NameInput;
  /** Public key to certify. */
  publicKey: PublicKeyLike;
  /** Key that signs the certificate (the CA key, or the subject's own key for a self-signed certificate). */
  signingKey: PrivateKeyLike;
  /** Issuer certificate; omit for a self-signed certificate. */
  issuer?: CertificateLike;
  /** Serial number bytes; a random positive 128-bit value by default. */
  serialNumber?: Uint8Array;
  notBefore?: Date;
  notAfter?: Date;
  /** Mark as CA certificate (basicConstraints cA=TRUE). */
  isCA?: boolean;
  pathLength?: number;
  digestAlgorithm?: DigestAlgorithm;
}

export function randomSerialNumber(): Buffer {
  const serial = randomBytes(16);
  serial[0] = serial[0]! & 0x7f;
  if (serial[0] === 0) serial[0] = 0x01;
  return serial;
}

/** Create and sign an X.509 v3 certificate. */
export function createCertificate(opts: CreateCertificateOptions): X509Certificate {
  const signingKey = toPrivateKey(opts.signingKey);
  const digestAlg = opts.digestAlgorithm ?? "sha256";
  const subject = buildName(opts.subject);
  const issuerCert = opts.issuer ? parseCertificateAsn(opts.issuer) : undefined;
  const issuer = issuerCert ? issuerCert.tbsCertificate.subject : subject;
  const notBefore = opts.notBefore ?? new Date(Date.now() - 5 * 60_000);
  const notAfter = opts.notAfter ?? new Date(notBefore.getTime() + 365 * 86_400_000);
  const issuerKey = opts.issuer ? toCertificate(opts.issuer).publicKey : toPublicKey(opts.signingKey);

  const exts: x509.Extension[] = [];
  if (opts.isCA !== undefined) {
    exts.push(
      makeExtension(
        OID.basicConstraints,
        new x509.BasicConstraints({ cA: opts.isCA, pathLenConstraint: opts.isCA ? opts.pathLength : undefined }),
        true,
      ),
    );
  }
  exts.push(makeExtension(OID.subjectKeyIdentifier, new x509.SubjectKeyIdentifier(keyIdentifier(opts.publicKey))));
  exts.push(
    makeExtension(
      OID.authorityKeyIdentifier,
      new x509.AuthorityKeyIdentifier({ keyIdentifier: new x509.KeyIdentifier(keyIdentifier(issuerKey)) }),
    ),
  );
  exts.push(...buildExtensions(opts));

  const sigAlg = signatureAlgorithm(signingKey, digestAlg);
  const tbs = new x509.TBSCertificate({
    version: x509.Version.v3,
    serialNumber: toArrayBuffer(withSignPadding(opts.serialNumber ?? randomSerialNumber())),
    signature: sigAlg,
    issuer,
    validity: new x509.Validity({ notBefore, notAfter }),
    subject,
    subjectPublicKeyInfo: spkiOf(opts.publicKey),
    extensions: new x509.Extensions(exts),
  });
  const tbsDer = serialize(tbs);
  const cert = new x509.Certificate({
    tbsCertificate: tbs,
    signatureAlgorithm: sigAlg,
    signatureValue: toArrayBuffer(sign(digestAlg, signingKey, tbsDer)),
  });
  return new X509Certificate(serialize(cert));
}

function withSignPadding(serial: Uint8Array): Buffer {
  const s = normalizeInteger(serial);
  return s[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), s]) : s;
}

/**
 * Create the self-signed certificate a SCEP client uses to sign its first request and to
 * receive the encrypted CertRep (RFC 8894 §2.3).
 */
export function createSelfSignedCertificate(opts: {
  subject: NameInput;
  privateKey: PrivateKeyLike;
  validityDays?: number;
  digestAlgorithm?: DigestAlgorithm;
}): X509Certificate {
  const privateKey = toPrivateKey(opts.privateKey);
  const notBefore = new Date(Date.now() - 5 * 60_000);
  return createCertificate({
    subject: opts.subject,
    publicKey: privateKey,
    signingKey: privateKey,
    notBefore,
    notAfter: new Date(notBefore.getTime() + (opts.validityDays ?? 30) * 86_400_000),
    digestAlgorithm: opts.digestAlgorithm,
    keyUsage: ["digitalSignature", "keyEncipherment"],
  });
}

// ---------------------------------------------------------------------------
// PKCS #10 certification requests
// ---------------------------------------------------------------------------

export interface CreateCsrOptions extends ExtensionOptions {
  subject: NameInput;
  privateKey: PrivateKeyLike;
  /** Shared secret for authorising the request (PKCS #9 challengePassword, RFC 8894 §2.2). */
  challengePassword?: string;
  digestAlgorithm?: DigestAlgorithm;
}

/** Create a DER-encoded PKCS #10 certification request. */
export function createCsr(opts: CreateCsrOptions): Buffer {
  const privateKey = toPrivateKey(opts.privateKey);
  const digestAlg = opts.digestAlgorithm ?? "sha256";
  const attributes: x509.Attribute[] = [];
  if (opts.challengePassword !== undefined) {
    const isPrintable = /^[A-Za-z0-9 '()+,\-./:=?]*$/.test(opts.challengePassword);
    const value = new ChallengePassword(
      isPrintable ? { printableString: opts.challengePassword } : { utf8String: opts.challengePassword },
    );
    attributes.push(new x509.Attribute({ type: OID.challengePassword, values: [AsnConvert.serialize(value)] }));
  }
  const exts = buildExtensions(opts);
  if (exts.length) {
    attributes.push(
      new x509.Attribute({ type: OID.extensionRequest, values: [AsnConvert.serialize(new ExtensionRequest(exts))] }),
    );
  }
  const info = new CertificationRequestInfo({
    version: 0,
    subject: buildName(opts.subject),
    subjectPKInfo: spkiOf(privateKey),
  });
  info.attributes.push(...attributes);
  const infoDer = serialize(info);
  const csr = new CertificationRequest({
    certificationRequestInfo: info,
    signatureAlgorithm: signatureAlgorithm(privateKey, digestAlg),
    signature: toArrayBuffer(sign(digestAlg, privateKey, infoDer)),
  });
  return serialize(csr);
}

export interface ParsedCsr {
  /** DER of the whole request. */
  der: Buffer;
  /** DER of the subject Name. */
  subject: Buffer;
  /** RFC 4514 rendering of the subject. */
  subjectString: string;
  publicKey: KeyObject;
  challengePassword?: string;
  /** Requested extensions (from the PKCS #9 extensionRequest attribute). */
  extensions: x509.Extension[];
  /** Whether the self-signature verifies. */
  signatureValid: boolean;
  asn: CertificationRequest;
}

/** Parse a DER (or PEM) PKCS #10 request and verify its self-signature. */
export function parseCsr(input: BytesLike | string): ParsedCsr {
  const der =
    typeof input === "string" ? (pemToDerList(input)[0] ?? Buffer.alloc(0)) : toBuffer(input as BytesLike);
  const asn = parse(der, CertificationRequest, "PKCS #10 request");
  const info = asn.certificationRequestInfo;
  const spkiDer = serialize(info.subjectPKInfo);
  const publicKey = toPublicKey(new Uint8Array(spkiDer));
  let challengePassword: string | undefined;
  const extensions: x509.Extension[] = [];
  for (const attr of info.attributes ?? []) {
    if (attr.type === OID.challengePassword && attr.values[0]) {
      challengePassword = AsnConvert.parse(attr.values[0], ChallengePassword).toString();
    } else if (attr.type === OID.extensionRequest && attr.values[0]) {
      extensions.push(...AsnConvert.parse(attr.values[0], ExtensionRequest));
    }
  }
  const infoDer = asn.certificationRequestInfoRaw ? toBuffer(asn.certificationRequestInfoRaw) : serialize(info);
  let signatureValid = false;
  try {
    const alg = digestAlgorithmFromOid(asn.signatureAlgorithm.algorithm);
    signatureValid = verify(alg, publicKey, infoDer, asn.signature);
  } catch {
    signatureValid = false;
  }
  return {
    der,
    subject: serialize(info.subject),
    subjectString: nameToString(info.subject),
    publicKey,
    challengePassword,
    extensions,
    signatureValid,
    asn,
  };
}

// ---------------------------------------------------------------------------
// Certificate revocation lists
// ---------------------------------------------------------------------------

export interface CreateCrlOptions {
  issuer: CertificateLike;
  signingKey: PrivateKeyLike;
  revoked?: Array<{ serialNumber: Uint8Array; revocationDate?: Date }>;
  thisUpdate?: Date;
  nextUpdate?: Date;
  digestAlgorithm?: DigestAlgorithm;
}

/** Create a DER-encoded X.509 v2 CRL. */
export function createCrl(opts: CreateCrlOptions): Buffer {
  const signingKey = toPrivateKey(opts.signingKey);
  const digestAlg = opts.digestAlgorithm ?? "sha256";
  const sigAlg = signatureAlgorithm(signingKey, digestAlg);
  const thisUpdate = opts.thisUpdate ?? new Date();
  const tbs = new x509.TBSCertList({
    version: x509.Version.v2,
    signature: sigAlg,
    issuer: parseCertificateAsn(opts.issuer).tbsCertificate.subject,
    thisUpdate: new x509.Time(thisUpdate),
    nextUpdate: new x509.Time(opts.nextUpdate ?? new Date(thisUpdate.getTime() + 7 * 86_400_000)),
    revokedCertificates: opts.revoked?.length
      ? opts.revoked.map(
          (r) =>
            new x509.RevokedCertificate({
              userCertificate: toArrayBuffer(withSignPadding(r.serialNumber)),
              revocationDate: new x509.Time(r.revocationDate ?? thisUpdate),
            }),
        )
      : undefined,
  });
  const crl = new x509.CertificateList({
    tbsCertList: tbs,
    signatureAlgorithm: sigAlg,
    signature: toArrayBuffer(sign(digestAlg, signingKey, serialize(tbs))),
  });
  return serialize(crl);
}

