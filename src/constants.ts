/** SCEP messageType values (RFC 8894 §3.2.1.2). */
export enum MessageType {
  /** Response to a certificate or CRL request. */
  CertRep = 3,
  /** Renewal request for an existing certificate. */
  RenewalReq = 17,
  /** Initial certificate enrolment request (PKCS #10). */
  PKCSReq = 19,
  /** Certificate polling in manual enrolment (formerly GetCertInitial). */
  CertPoll = 20,
  /** Retrieve a certificate by issuer and serial number. */
  GetCert = 21,
  /** Retrieve a CRL. */
  GetCRL = 22,
}

/** SCEP pkiStatus values (RFC 8894 §3.2.1.3). */
export enum PkiStatus {
  SUCCESS = 0,
  FAILURE = 2,
  PENDING = 3,
}

/** SCEP failInfo values (RFC 8894 §3.2.1.4). */
export enum FailInfo {
  /** Unrecognized or unsupported algorithm. */
  badAlg = 0,
  /** Integrity check (meaning signature verification of the CMS message) failed. */
  badMessageCheck = 1,
  /** Transaction not permitted or supported. */
  badRequest = 2,
  /** The signingTime attribute from the CMS authenticatedAttributes was not sufficiently close to the system time. */
  badTime = 3,
  /** No certificate could be identified matching the provided criteria. */
  badCertId = 4,
}

/** CA capability keywords returned by GetCACaps (RFC 8894 §3.5.2). Matching is case-insensitive. */
export enum Capability {
  AES = "AES",
  DES3 = "DES3",
  GetNextCACert = "GetNextCACert",
  POSTPKIOperation = "POSTPKIOperation",
  Renewal = "Renewal",
  SHA1 = "SHA-1",
  SHA256 = "SHA-256",
  SHA512 = "SHA-512",
  SCEPStandard = "SCEPStandard",
}

/** HTTP "operation" values (RFC 8894 §4). */
export enum Operation {
  GetCACert = "GetCACert",
  GetCACaps = "GetCACaps",
  GetNextCACert = "GetNextCACert",
  PKIOperation = "PKIOperation",
}

/** MIME types used by SCEP over HTTP (RFC 8894 §4). */
export const ContentTypes = {
  /** GetCACert response: a single DER-encoded CA certificate. */
  caCert: "application/x-x509-ca-cert",
  /** GetCACert response: degenerate certificates-only CMS SignedData with CA and RA certificates. */
  caRaCert: "application/x-x509-ca-ra-cert",
  /** GetNextCACert response: CMS SignedData, signed by the current CA, carrying the next CA (and RA) certificates. */
  nextCaCert: "application/x-x509-next-ca-cert",
  /** PKIOperation request (POST) and response body. */
  pkiMessage: "application/x-pki-message",
  /** GetCACaps response. */
  text: "text/plain",
} as const;

/** Default CGI path historically used by SCEP servers. */
export const DEFAULT_SCEP_PATH = "/cgi-bin/pkiclient.exe";

/** Supported digest algorithms. */
export type DigestAlgorithm = "sha1" | "sha256" | "sha384" | "sha512";

/**
 * Supported content-encryption algorithms. `des-cbc` (single DES) is obsolete and only
 * supported for interoperability with legacy servers; it is never selected automatically.
 */
export type EncryptionAlgorithm = "aes-128-cbc" | "aes-192-cbc" | "aes-256-cbc" | "des-ede3-cbc" | "des-cbc";

/** RSAES-OAEP parameters (RFC 8017 §7.1, RFC 4055 §4.1). MGF1 always uses the same hash. */
export interface RsaOaepParams {
  scheme: "rsa-oaep";
  /** Hash for OAEP and MGF1 (default sha256). */
  hash?: DigestAlgorithm;
  /** Encoding parameters (the OAEP label), carried as pSpecified. Empty by default. */
  label?: Uint8Array;
}

/**
 * Key-transport scheme used to encrypt the content-encryption key of a pkcsPKIEnvelope.
 * `rsa-pkcs1` is RSAES-PKCS1-v1_5, which every SCEP implementation supports; `rsa-oaep` is
 * shorthand for RSAES-OAEP with SHA-256. RFC 8894 defines no capability keyword for OAEP,
 * so it must be enabled explicitly.
 */
export type KeyTransportAlgorithm = "rsa-pkcs1" | "rsa-oaep" | RsaOaepParams;
