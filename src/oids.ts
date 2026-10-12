/**
 * Object identifiers used by SCEP (RFC 8894) and the CMS / PKCS structures it builds on.
 */
export const OID = {
  // CMS content types (RFC 5652)
  data: "1.2.840.113549.1.7.1",
  signedData: "1.2.840.113549.1.7.2",
  envelopedData: "1.2.840.113549.1.7.3",

  // PKCS #9 attributes
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  signingTime: "1.2.840.113549.1.9.5",
  challengePassword: "1.2.840.113549.1.9.7",
  extensionRequest: "1.2.840.113549.1.9.14",
  emailAddress: "1.2.840.113549.1.9.1",

  // Public key / signature algorithms
  rsaEncryption: "1.2.840.113549.1.1.1",
  sha1WithRSAEncryption: "1.2.840.113549.1.1.5",
  sha256WithRSAEncryption: "1.2.840.113549.1.1.11",
  sha384WithRSAEncryption: "1.2.840.113549.1.1.12",
  sha512WithRSAEncryption: "1.2.840.113549.1.1.13",
  sha224WithRSAEncryption: "1.2.840.113549.1.1.14",

  // Digest algorithms
  sha1: "1.3.14.3.2.26",
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  sha224: "2.16.840.1.101.3.4.2.4",
  md5: "1.2.840.113549.2.5",

  // Content-encryption algorithms
  aes128CBC: "2.16.840.1.101.3.4.1.2",
  aes192CBC: "2.16.840.1.101.3.4.1.22",
  aes256CBC: "2.16.840.1.101.3.4.1.42",
  desEde3CBC: "1.2.840.113549.3.7",
  desCBC: "1.3.14.3.2.7",

  // SCEP signed attributes: id-VeriSign(2.16.840.1.113733) pki(1) attributes(9)
  scepMessageType: "2.16.840.1.113733.1.9.2",
  scepPkiStatus: "2.16.840.1.113733.1.9.3",
  scepFailInfo: "2.16.840.1.113733.1.9.4",
  scepSenderNonce: "2.16.840.1.113733.1.9.5",
  scepRecipientNonce: "2.16.840.1.113733.1.9.6",
  scepTransactionId: "2.16.840.1.113733.1.9.7",
  // id-scep-failInfoText: id-pkix(1.3.6.1.5.5.7) id-scep(24) 1
  scepFailInfoText: "1.3.6.1.5.5.7.24.1",

  // X.509 extensions
  subjectKeyIdentifier: "2.5.29.14",
  keyUsage: "2.5.29.15",
  subjectAltName: "2.5.29.17",
  basicConstraints: "2.5.29.19",
  authorityKeyIdentifier: "2.5.29.35",
  extKeyUsage: "2.5.29.37",
} as const;
