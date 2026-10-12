import type { X509Certificate } from "node:crypto";
import { KeyUsageFlags } from "@peculiar/asn1-x509";
import { ScepError } from "./errors.js";
import { certificateKeyUsage, isIssuedBy, sameCertificate } from "./x509.js";

/**
 * The CA (and optional RA) certificates returned by GetCACert, classified by role
 * (RFC 8894 §4.2). When an RA is in use, requests are encrypted for the RA's encryption
 * certificate and responses are signed by the RA's signing certificate.
 */
export class CACertificates {
  /** The issuing CA certificate. */
  public readonly ca: X509Certificate;
  /** RA certificates (non-CA certificates), if any. */
  public readonly ra: X509Certificate[];

  constructor(public readonly all: X509Certificate[]) {
    if (all.length === 0) throw new ScepError("No CA certificates");
    const cas = all.filter((c) => c.ca);
    this.ra = all.filter((c) => !c.ca);
    if (cas.length === 0) {
      // Some deployments return CA certificates without basicConstraints; assume the first.
      this.ca = all[0]!;
      this.ra = all.slice(1);
    } else {
      // The issuing CA is the CA certificate that did not issue another CA certificate in the set,
      // preferring one that issued an RA certificate.
      const leafCas = cas.filter((c) => !cas.some((o) => o !== c && !sameCertificate(o, c) && isIssuedBy(o, c)));
      this.ca =
        leafCas.find((c) => this.ra.some((r) => isIssuedBy(r, c))) ?? leafCas[0] ?? cas[cas.length - 1]!;
    }
  }

  /** Certificate a client encrypts its pkcsPKIEnvelope for. */
  get encryptionCertificate(): X509Certificate {
    return this.pick(KeyUsageFlags.keyEncipherment) ?? this.ca;
  }

  /** Certificate expected to sign CertRep messages. */
  get signingCertificate(): X509Certificate {
    return this.pick(KeyUsageFlags.digitalSignature) ?? this.ca;
  }

  /** True if `cert` belongs to this set or was issued by the CA (e.g. a rolled-over RA certificate). */
  isTrustedSigner(cert: X509Certificate): boolean {
    return this.all.some((c) => sameCertificate(c, cert)) || isIssuedBy(cert, this.ca);
  }

  private pick(flag: KeyUsageFlags): X509Certificate | undefined {
    if (this.ra.length === 0) return undefined;
    return (
      this.ra.find((c) => {
        const ku = certificateKeyUsage(c);
        return ku !== undefined && (ku & flag) !== 0;
      }) ?? this.ra.find((c) => certificateKeyUsage(c) === undefined) ?? this.ra[0]
    );
  }
}
