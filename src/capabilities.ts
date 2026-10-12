import { Capability, type DigestAlgorithm, type EncryptionAlgorithm } from "./constants.js";

/**
 * The capability set returned by GetCACaps (RFC 8894 §3.5.2), with the algorithm
 * negotiation rules a client applies to it.
 */
export class CACapabilities {
  private readonly set: Set<string>;

  constructor(public readonly keywords: readonly string[]) {
    this.set = new Set(keywords.map((k) => k.trim().toLowerCase()).filter(Boolean));
  }

  /** Parse a GetCACaps response body (one keyword per line, case-insensitive). */
  static parse(text: string): CACapabilities {
    return new CACapabilities(
      text
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean),
    );
  }

  has(capability: Capability | string): boolean {
    return this.set.has(capability.toLowerCase());
  }

  /** SCEPStandard implies AES, POSTPKIOperation and SHA-256 (RFC 8894 §3.5.2). */
  get scepStandard(): boolean {
    return this.has(Capability.SCEPStandard);
  }

  get supportsPost(): boolean {
    return this.scepStandard || this.has(Capability.POSTPKIOperation);
  }

  get supportsRenewal(): boolean {
    return this.has(Capability.Renewal);
  }

  get supportsGetNextCACert(): boolean {
    return this.has(Capability.GetNextCACert);
  }

  get supportsAes(): boolean {
    return this.scepStandard || this.has(Capability.AES);
  }

  /** Strongest content-encryption algorithm the CA advertises. */
  get encryptionAlgorithm(): EncryptionAlgorithm {
    if (this.supportsAes) return "aes-128-cbc";
    // Single DES is not supported by modern crypto libraries; DES3 is the legacy fallback.
    return "des-ede3-cbc";
  }

  /** Preferred digest algorithm the CA advertises. */
  get digestAlgorithm(): DigestAlgorithm {
    if (this.scepStandard || this.has(Capability.SHA256)) return "sha256";
    if (this.has(Capability.SHA512)) return "sha512";
    return "sha1";
  }

  toString(): string {
    return this.keywords.join("\n");
  }
}
