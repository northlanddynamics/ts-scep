/**
 * SCEP client (RFC 8894 §4): CA discovery, enrolment, renewal, polling and certificate/CRL
 * retrieval over HTTP.
 */
import { X509Certificate } from "node:crypto";
import { CACapabilities } from "./capabilities.js";
import { CACertificates } from "./ca-certificates.js";
import { parseSignedData, verifySignerInfo } from "./cms.js";
import {
  ContentTypes,
  MessageType,
  Operation,
  PkiStatus,
  type DigestAlgorithm,
  type EncryptionAlgorithm,
} from "./constants.js";
import { randomBytes, toPrivateKey, type PrivateKeyLike } from "./crypto.js";
import { ScepError, ScepFailureError, ScepHttpError, ScepProtocolError } from "./errors.js";
import {
  decodePkiMessage,
  encodeIssuerAndSerialNumber,
  encodeIssuerAndSubject,
  encodePkiMessage,
  NONCE_LENGTH,
  transactionIdFromPublicKey,
  type PkiMessage,
  type ScepIdentity,
} from "./message.js";
import { bytesEqual, toBuffer, type BytesLike } from "./util.js";
import {
  certificateIssuer,
  certificateSerialNumber,
  certificateSubject,
  createSelfSignedCertificate,
  parseCertificates,
  parseCsr,
  samePublicKey,
  type CertificateLike,
  type NameInput,
  encodeName,
  toCertificate,
} from "./x509.js";

export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

export interface ScepClientOptions {
  /** SCEP endpoint, e.g. `http://ca.example.com/cgi-bin/pkiclient.exe`. */
  url: string | URL;
  /** Value of the `message` parameter for GetCACert/GetCACaps/GetNextCACert (a CA identifier). */
  caIdentifier?: string;
  /**
   * Expected fingerprint (SHA-256 or SHA-1, hex with or without colons) of the CA certificate.
   * Strongly recommended: GetCACert runs over unauthenticated HTTP (RFC 8894 §2.2).
   */
  caFingerprint?: string;
  /** Pre-provisioned CA/RA certificates; GetCACert is skipped when given. */
  caCertificates?: CertificateLike[];
  /** Pre-known capabilities; GetCACaps is skipped when given. */
  capabilities?: string[];
  /** Override the negotiated digest algorithm. */
  digestAlgorithm?: DigestAlgorithm;
  /** Override the negotiated content-encryption algorithm. */
  encryptionAlgorithm?: EncryptionAlgorithm;
  /** Force (true) or forbid (false) HTTP POST for PKIOperation. Negotiated from capabilities by default. */
  usePost?: boolean;
  /** Extra HTTP headers on every request. */
  headers?: Record<string, string>;
  /** Request timeout in milliseconds (default 60 s). */
  timeoutMs?: number;
  /** Custom fetch implementation (defaults to the global fetch). */
  fetch?: FetchLike;
}

export interface EnrollOptions {
  /** DER (or PEM) PKCS #10 request. */
  csr: BytesLike | string;
  /** Private key matching the request's public key. */
  privateKey: PrivateKeyLike;
  /**
   * Existing identity to sign the request with: a certificate previously issued by this CA,
   * for renewal or re-enrolment. Defaults to a fresh self-signed certificate for `privateKey`.
   */
  signer?: { certificate: CertificateLike; privateKey: PrivateKeyLike };
  /**
   * Send a RenewalReq instead of a PKCSReq. Defaults to true when `signer` is given and the
   * CA advertises the Renewal capability.
   */
  renewal?: boolean;
  /** transactionID; defaults to a hash of the request's public key. */
  transactionId?: string;
}

/** State needed to poll for a pending (manually approved) enrolment. */
export interface PendingEnrollment {
  transactionId: string;
  /** DER issuer Name (the CA). */
  issuer: Buffer;
  /** DER subject Name from the request. */
  subject: Buffer;
  /** Identity that signed the original request; polls must be signed by it too. */
  identity: ScepIdentity;
  /** DER PKCS #10 request (used to select the issued certificate). */
  csr: Buffer;
}

export type EnrollmentResult =
  | {
      status: PkiStatus.SUCCESS;
      transactionId: string;
      /** The newly issued certificate. */
      certificate: X509Certificate;
      /** Every certificate in the CertRep (issued certificate plus any chain). */
      certificates: X509Certificate[];
      response: PkiMessage;
    }
  | {
      status: PkiStatus.PENDING;
      transactionId: string;
      /** Pass to {@link ScepClient.poll} or {@link ScepClient.waitForCertificate}. */
      pending: PendingEnrollment;
      response: PkiMessage;
    };

export class ScepClient {
  private readonly url: URL;
  private readonly fetchImpl: FetchLike;
  private caCertsPromise?: Promise<CACertificates>;
  private capsPromise?: Promise<CACapabilities>;

  constructor(private readonly options: ScepClientOptions) {
    this.url = new URL(options.url);
    const f = options.fetch ?? (globalThis.fetch as FetchLike | undefined);
    if (!f) throw new ScepError("No fetch implementation available");
    this.fetchImpl = f;
    if (options.caCertificates) {
      this.caCertsPromise = Promise.resolve(new CACertificates(options.caCertificates.map(toCertificate)));
    }
    if (options.capabilities) this.capsPromise = Promise.resolve(new CACapabilities(options.capabilities));
  }

  // -------------------------------------------------------------------------
  // CA discovery
  // -------------------------------------------------------------------------

  /**
   * GetCACaps (RFC 8894 §3.5.1). Cached after the first call. A server that answers with an
   * HTTP error predates GetCACaps and is treated as advertising no capabilities.
   */
  getCACaps(): Promise<CACapabilities> {
    this.capsPromise ??= this.get(Operation.GetCACaps, this.options.caIdentifier)
      .then(async (res) => CACapabilities.parse(new TextDecoder().decode(await this.body(res))))
      .catch((err) => {
        if (err instanceof ScepHttpError && err.status >= 400 && err.status < 500) return new CACapabilities([]);
        this.capsPromise = undefined;
        throw err;
      });
    return this.capsPromise;
  }

  /** GetCACert (RFC 8894 §4.2). Cached after the first call. */
  getCACert(): Promise<CACertificates> {
    this.caCertsPromise ??= this.fetchCACert().catch((err) => {
      this.caCertsPromise = undefined;
      throw err;
    });
    return this.caCertsPromise;
  }

  private async fetchCACert(): Promise<CACertificates> {
    const res = await this.get(Operation.GetCACert, this.options.caIdentifier);
    const body = await this.body(res);
    const type = (res.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
    let certs: X509Certificate[];
    if (type === ContentTypes.caCert) {
      certs = [new X509Certificate(body)];
    } else if (type === ContentTypes.caRaCert) {
      certs = parseSignedData(body).certificates;
    } else {
      certs = parseCaCertBody(body);
    }
    const ca = new CACertificates(certs);
    if (this.options.caFingerprint) checkFingerprint(ca, this.options.caFingerprint);
    return ca;
  }

  /**
   * GetNextCACert (RFC 8894 §4.7): retrieve the CA's rollover certificates. The response is
   * verified against the current CA certificate.
   */
  async getNextCACert(): Promise<X509Certificate[]> {
    const current = await this.getCACert();
    const res = await this.get(Operation.GetNextCACert, this.options.caIdentifier);
    const sd = parseSignedData(await this.body(res));
    if (sd.signerInfos.length === 0) throw new ScepProtocolError("GetNextCACert response is not signed");
    const signer = verifySignerInfo(sd, sd.signerInfos[0]!, current.all);
    if (!current.isTrustedSigner(signer.certificate)) {
      throw new ScepProtocolError("GetNextCACert response not signed by the current CA");
    }
    if (sd.content?.length) return parseSignedData(sd.content).certificates;
    return sd.certificates.filter((c) => !c.raw.equals(signer.certificate.raw));
  }

  // -------------------------------------------------------------------------
  // Enrolment
  // -------------------------------------------------------------------------

  /**
   * Enrol (PKCSReq) or renew (RenewalReq) a certificate (RFC 8894 §3.3.1).
   * Resolves with the issued certificate or a pending state; throws {@link ScepFailureError}
   * when the CA rejects the request.
   */
  async enroll(opts: EnrollOptions): Promise<EnrollmentResult> {
    const csr = parseCsr(typeof opts.csr === "string" ? opts.csr : toBuffer(opts.csr));
    const privateKey = toPrivateKey(opts.privateKey);
    if (!samePublicKey(privateKey, csr.publicKey)) {
      throw new ScepError("privateKey does not match the certification request");
    }
    const [ca, caps] = await Promise.all([this.getCACert(), this.getCACaps()]);

    const identity: ScepIdentity = opts.signer
      ? { certificate: toCertificate(opts.signer.certificate), privateKey: toPrivateKey(opts.signer.privateKey) }
      : {
          certificate: createSelfSignedCertificate({
            subject: csr.subject,
            privateKey,
            digestAlgorithm: this.digestFor(caps),
          }),
          privateKey,
        };

    const renewal = opts.renewal ?? (!!opts.signer && caps.supportsRenewal);
    const transactionId = opts.transactionId ?? transactionIdFromPublicKey(csr.publicKey);
    const pending: PendingEnrollment = {
      transactionId,
      issuer: certificateSubject(ca.ca),
      subject: csr.subject,
      identity,
      csr: csr.der,
    };
    const response = await this.transact(
      renewal ? MessageType.RenewalReq : MessageType.PKCSReq,
      transactionId,
      csr.der,
      identity,
      ca,
      caps,
    );
    return this.enrollmentResult(response, pending);
  }

  /** Poll once for a pending enrolment (CertPoll, RFC 8894 §3.3.3). */
  async poll(pending: PendingEnrollment): Promise<EnrollmentResult> {
    const [ca, caps] = await Promise.all([this.getCACert(), this.getCACaps()]);
    const response = await this.transact(
      MessageType.CertPoll,
      pending.transactionId,
      encodeIssuerAndSubject(pending.issuer, pending.subject),
      pending.identity,
      ca,
      caps,
    );
    return this.enrollmentResult(response, pending);
  }

  /** Poll until the enrolment is approved or rejected, or the timeout elapses. */
  async waitForCertificate(
    pending: PendingEnrollment,
    opts: { intervalMs?: number; timeoutMs?: number; signal?: AbortSignal } = {},
  ): Promise<Extract<EnrollmentResult, { status: PkiStatus.SUCCESS }>> {
    const interval = opts.intervalMs ?? 60_000;
    const deadline = opts.timeoutMs !== undefined ? Date.now() + opts.timeoutMs : Infinity;
    for (;;) {
      opts.signal?.throwIfAborted();
      const result = await this.poll(pending);
      if (result.status === PkiStatus.SUCCESS) return result;
      if (Date.now() + interval > deadline) throw new ScepError("Timed out waiting for certificate issuance");
      await new Promise<void>((resolve, reject) => {
        const t = setTimeout(resolve, interval);
        opts.signal?.addEventListener("abort", () => (clearTimeout(t), reject(opts.signal!.reason)), { once: true });
      });
    }
  }

  // -------------------------------------------------------------------------
  // Certificate and CRL access
  // -------------------------------------------------------------------------

  /** GetCert (RFC 8894 §3.3.4): retrieve a certificate by issuer and serial number. */
  async getCert(opts: {
    serialNumber: BytesLike;
    /** Issuer name; defaults to the CA's subject. */
    issuer?: NameInput;
    /** Identity to sign the request with (typically a certificate issued by this CA). */
    signer: { certificate: CertificateLike; privateKey: PrivateKeyLike };
    transactionId?: string;
  }): Promise<X509Certificate[]> {
    const [ca, caps] = await Promise.all([this.getCACert(), this.getCACaps()]);
    const identity = toIdentity(opts.signer);
    const issuer = opts.issuer !== undefined ? encodeName(opts.issuer) : certificateSubject(ca.ca);
    const response = await this.transact(
      MessageType.GetCert,
      opts.transactionId ?? transactionIdFromPublicKey(identity.certificate.publicKey),
      encodeIssuerAndSerialNumber(issuer, opts.serialNumber),
      identity,
      ca,
      caps,
    );
    return this.successCertificates(response).certificates;
  }

  /**
   * GetCRL (RFC 8894 §3.3.5): retrieve the CRL covering `certificate` (which defaults to the
   * signer's certificate). Returns the DER-encoded CRL.
   */
  async getCRL(opts: {
    signer: { certificate: CertificateLike; privateKey: PrivateKeyLike };
    certificate?: CertificateLike;
    transactionId?: string;
  }): Promise<Buffer> {
    const [ca, caps] = await Promise.all([this.getCACert(), this.getCACaps()]);
    const identity = toIdentity(opts.signer);
    const target = opts.certificate ? toCertificate(opts.certificate) : identity.certificate;
    const response = await this.transact(
      MessageType.GetCRL,
      opts.transactionId ?? transactionIdFromPublicKey(identity.certificate.publicKey),
      encodeIssuerAndSerialNumber(certificateIssuer(target), certificateSerialNumber(target)),
      identity,
      ca,
      caps,
    );
    const { crls } = this.successCertificates(response);
    if (!crls[0]) throw new ScepProtocolError("CertRep did not contain a CRL");
    return crls[0];
  }

  // -------------------------------------------------------------------------
  // Transport
  // -------------------------------------------------------------------------

  /** Send a raw pkiMessage and return the raw response (PKIOperation, RFC 8894 §4.3). */
  async pkiOperation(message: BytesLike, usePost?: boolean): Promise<Buffer> {
    const post = usePost ?? this.options.usePost ?? (await this.getCACaps()).supportsPost;
    const res = post
      ? await this.request(this.operationUrl(Operation.PKIOperation), {
          method: "POST",
          headers: { "content-type": ContentTypes.pkiMessage },
          body: toBuffer(message),
        })
      : await this.get(Operation.PKIOperation, toBuffer(message).toString("base64"));
    return this.body(res);
  }

  private async transact(
    messageType: MessageType,
    transactionId: string,
    messageData: Buffer,
    identity: ScepIdentity,
    ca: CACertificates,
    caps: CACapabilities,
  ): Promise<PkiMessage> {
    const senderNonce = randomBytes(NONCE_LENGTH);
    const request = encodePkiMessage({
      messageType,
      transactionId,
      senderNonce,
      messageData,
      recipient: ca.encryptionCertificate,
      signer: identity,
      digestAlgorithm: this.digestFor(caps),
      encryptionAlgorithm: this.options.encryptionAlgorithm ?? caps.encryptionAlgorithm,
    });
    const raw = await this.pkiOperation(request, this.options.usePost ?? caps.supportsPost);
    const response = decodePkiMessage(raw, { recipient: identity, signerCertificates: ca.all });

    if (response.messageType !== MessageType.CertRep) {
      throw new ScepProtocolError(`Expected CertRep, received messageType ${response.messageType}`);
    }
    if (!ca.isTrustedSigner(response.signerCertificate)) {
      throw new ScepProtocolError("CertRep is not signed by the CA or an RA");
    }
    if (response.transactionId !== transactionId) throw new ScepProtocolError("CertRep transactionID mismatch");
    if (!response.recipientNonce || !bytesEqual(response.recipientNonce, senderNonce)) {
      throw new ScepProtocolError("CertRep recipientNonce does not match the request senderNonce");
    }
    if (response.pkiStatus === PkiStatus.FAILURE) {
      throw new ScepFailureError(response.failInfo, response.failInfoText, transactionId);
    }
    return response;
  }

  private enrollmentResult(response: PkiMessage, pending: PendingEnrollment): EnrollmentResult {
    if (response.pkiStatus === PkiStatus.PENDING) {
      return { status: PkiStatus.PENDING, transactionId: pending.transactionId, pending, response };
    }
    const { certificates } = this.successCertificates(response);
    const requestedKey = parseCsr(pending.csr).publicKey;
    const certificate = certificates.find((c) => samePublicKey(c.publicKey, requestedKey));
    if (!certificate) throw new ScepProtocolError("CertRep does not contain a certificate for the requested key");
    return { status: PkiStatus.SUCCESS, transactionId: pending.transactionId, certificate, certificates, response };
  }

  private successCertificates(response: PkiMessage): { certificates: X509Certificate[]; crls: Buffer[] } {
    if (response.pkiStatus !== PkiStatus.SUCCESS) {
      throw new ScepProtocolError(`Unexpected pkiStatus ${response.pkiStatus}`);
    }
    if (!response.messageData) throw new ScepProtocolError("Successful CertRep has no pkcsPKIEnvelope");
    const inner = parseSignedData(response.messageData);
    return { certificates: inner.certificates, crls: inner.crls };
  }

  private digestFor(caps: CACapabilities): DigestAlgorithm {
    return this.options.digestAlgorithm ?? caps.digestAlgorithm;
  }

  private operationUrl(operation: Operation, message?: string): URL {
    const url = new URL(this.url);
    url.searchParams.set("operation", operation);
    if (message !== undefined) url.searchParams.set("message", message);
    return url;
  }

  private get(operation: Operation, message?: string): Promise<Response> {
    return this.request(this.operationUrl(operation, message), { method: "GET" });
  }

  private async request(url: URL, init: RequestInit): Promise<Response> {
    const res = await this.fetchImpl(url, {
      ...init,
      headers: { ...this.options.headers, ...(init.headers as Record<string, string> | undefined) },
      signal: AbortSignal.timeout(this.options.timeoutMs ?? 60_000),
    });
    if (!res.ok) {
      const body = new Uint8Array(await res.arrayBuffer().catch(() => new ArrayBuffer(0)));
      throw new ScepHttpError(`SCEP server responded with HTTP ${res.status}`, res.status, body);
    }
    return res;
  }

  private async body(res: Response): Promise<Buffer> {
    return Buffer.from(await res.arrayBuffer());
  }
}

function toIdentity(signer: { certificate: CertificateLike; privateKey: PrivateKeyLike }): ScepIdentity {
  return { certificate: toCertificate(signer.certificate), privateKey: toPrivateKey(signer.privateKey) };
}

function parseCaCertBody(body: Buffer): X509Certificate[] {
  const text = body.toString("latin1");
  if (text.includes("-----BEGIN CERTIFICATE-----")) return parseCertificates(text);
  try {
    return [new X509Certificate(body)];
  } catch {
    return parseSignedData(body).certificates;
  }
}

function checkFingerprint(ca: CACertificates, expected: string): void {
  const want = expected.replace(/[^0-9a-f]/gi, "").toUpperCase();
  const match = ca.all.some((c) =>
    [c.fingerprint256, c.fingerprint].some((fp) => fp.replace(/:/g, "").toUpperCase() === want),
  );
  if (!match) throw new ScepError("CA certificate fingerprint does not match the expected value");
}
