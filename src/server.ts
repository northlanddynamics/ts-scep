/**
 * SCEP server (CA / RA side, RFC 8894 §4): serves GetCACaps, GetCACert, GetNextCACert and
 * PKIOperation, delegating authorisation and issuance decisions to a {@link ScepHandler}.
 *
 * The server is framework-agnostic: use {@link ScepServer.handle} with any HTTP stack,
 * {@link ScepServer.fetchHandler} with Fetch-API runtimes, or {@link ScepServer.nodeHandler}
 * with `node:http` / Express.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import type { X509Certificate } from "node:crypto";
import { createDegenerateSignedData, createSignedData } from "./cms.js";
import {
  Capability,
  ContentTypes,
  FailInfo,
  MessageType,
  Operation,
  PkiStatus,
  type DigestAlgorithm,
} from "./constants.js";
import { toPrivateKey, type PrivateKeyLike } from "./crypto.js";
import { ScepError, ScepProtocolError } from "./errors.js";
import {
  decodeIssuerAndSerialNumber,
  decodeIssuerAndSubject,
  decodePkiMessage,
  encodePkiMessage,
  peekPkiMessage,
  type PkiMessage,
  type ScepIdentity,
} from "./message.js";
import { toBuffer, type BytesLike } from "./util.js";
import {
  isIssuedBy,
  isSelfSigned,
  parseCsr,
  samePublicKey,
  toCertificate,
  type CertificateLike,
  type ParsedCsr,
} from "./x509.js";

/** Context common to every PKIOperation passed to a handler. */
export interface ScepRequestContext {
  /** The verified, decrypted request. */
  message: PkiMessage;
  transactionId: string;
  /** Certificate that signed the request. */
  signerCertificate: X509Certificate;
  /** True if the signer certificate is self-signed (a first-time enrolment). */
  selfSigned: boolean;
  /** True if the signer certificate was issued by this CA (renewal / re-enrolment). */
  signerIssuedByCa: boolean;
}

/** PKCSReq or RenewalReq. The CSR signature has already been verified. */
export interface EnrollmentRequest extends ScepRequestContext {
  csr: ParsedCsr;
  renewal: boolean;
}

/** CertPoll. */
export interface PollRequest extends ScepRequestContext {
  /** DER issuer Name. */
  issuer: Buffer;
  /** DER subject Name. */
  subject: Buffer;
}

/** GetCert or GetCRL. */
export interface IssuerAndSerialRequest extends ScepRequestContext {
  /** DER issuer Name. */
  issuer: Buffer;
  /** Serial number bytes (no sign padding). */
  serialNumber: Buffer;
}

/** Outcome of a handler. */
export type ScepResult =
  | {
      status: "success";
      /** Issued/requested certificates (issued certificate first), returned in a degenerate SignedData. */
      certificates?: CertificateLike[];
      /** DER-encoded CRLs (GetCRL). */
      crls?: BytesLike[];
    }
  | { status: "pending" }
  | { status: "failure"; failInfo?: FailInfo; failInfoText?: string };

export interface ScepHandler {
  /** PKCSReq and RenewalReq. Verify the challenge password / authorisation here and issue. */
  enroll(request: EnrollmentRequest): ScepResult | Promise<ScepResult>;
  /** CertPoll for a previously pending enrolment. */
  poll?(request: PollRequest): ScepResult | Promise<ScepResult>;
  /** GetCert. */
  getCert?(request: IssuerAndSerialRequest): ScepResult | Promise<ScepResult>;
  /** GetCRL. */
  getCRL?(request: IssuerAndSerialRequest): ScepResult | Promise<ScepResult>;
}

export interface ScepServerOptions {
  /** The issuing CA. `privateKey` is required unless an RA handles messages, and for GetNextCACert. */
  ca: { certificate: CertificateLike; privateKey?: PrivateKeyLike; chain?: CertificateLike[] };
  /** Registration authority that decrypts requests and signs responses on behalf of the CA. */
  ra?: { certificate: CertificateLike; privateKey: PrivateKeyLike };
  /** Rollover CA (and RA) certificates served by GetNextCACert. */
  nextCaCertificates?: CertificateLike[];
  /** Capabilities advertised by GetCACaps. Sensible RFC 8894 defaults are used when omitted. */
  capabilities?: string[];
  /** Reject requests whose signingTime differs from local time by more than this (badTime). */
  maxClockSkewMs?: number;
  handler: ScepHandler;
}

/** Transport-neutral HTTP request. */
export interface ScepHttpRequest {
  method: string;
  /** Query parameters (`operation`, `message`). */
  query: URLSearchParams | Record<string, string | string[] | undefined>;
  body?: Uint8Array;
}

export interface ScepHttpResponse {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
}

export class ScepServer {
  private readonly caCert: X509Certificate;
  private readonly caKey?: ReturnType<typeof toPrivateKey>;
  private readonly chain: X509Certificate[];
  private readonly identity: ScepIdentity;
  private readonly raCert?: X509Certificate;
  private readonly nextCa: X509Certificate[];
  public readonly capabilities: string[];

  constructor(private readonly options: ScepServerOptions) {
    this.caCert = toCertificate(options.ca.certificate);
    this.caKey = options.ca.privateKey ? toPrivateKey(options.ca.privateKey) : undefined;
    this.chain = (options.ca.chain ?? []).map(toCertificate);
    this.nextCa = (options.nextCaCertificates ?? []).map(toCertificate);
    if (options.ra) {
      this.raCert = toCertificate(options.ra.certificate);
      this.identity = { certificate: this.raCert, privateKey: toPrivateKey(options.ra.privateKey) };
    } else {
      if (!this.caKey) throw new ScepError("ca.privateKey is required when no RA is configured");
      this.identity = { certificate: this.caCert, privateKey: this.caKey };
    }
    if (this.nextCa.length && !this.caKey) throw new ScepError("GetNextCACert requires ca.privateKey");
    this.capabilities = options.capabilities ?? [
      Capability.AES,
      Capability.DES3,
      ...(this.nextCa.length ? [Capability.GetNextCACert] : []),
      Capability.POSTPKIOperation,
      Capability.Renewal,
      Capability.SHA1,
      Capability.SHA256,
      Capability.SHA512,
      Capability.SCEPStandard,
    ];
  }

  // -------------------------------------------------------------------------
  // HTTP entry points
  // -------------------------------------------------------------------------

  /** Handle a SCEP HTTP request. Never throws; protocol errors become HTTP 4xx/5xx responses. */
  async handle(req: ScepHttpRequest): Promise<ScepHttpResponse> {
    const param = (name: string): string | undefined => {
      if (req.query instanceof URLSearchParams) return req.query.get(name) ?? undefined;
      const v = req.query[name];
      return Array.isArray(v) ? v[0] : v;
    };
    try {
      const operation = param("operation");
      switch (operation) {
        case Operation.GetCACaps:
          return respond(200, ContentTypes.text, Buffer.from(this.capabilities.join("\n") + "\n"));
        case Operation.GetCACert:
          return this.getCACert();
        case Operation.GetNextCACert:
          return this.getNextCACert();
        case Operation.PKIOperation: {
          const method = req.method.toUpperCase();
          let message: Buffer | undefined;
          if (method === "POST") message = req.body ? toBuffer(req.body) : undefined;
          else if (method === "GET") {
            // Unescaped '+' in base64 decodes as ' ' in query strings.
            const m = param("message");
            message = m ? Buffer.from(m.replace(/ /g, "+"), "base64") : undefined;
          } else return respond(405, ContentTypes.text, Buffer.from("Method not allowed\n"));
          if (!message?.length) return respond(400, ContentTypes.text, Buffer.from("Missing message\n"));
          return respond(200, ContentTypes.pkiMessage, await this.pkiOperation(message));
        }
        default:
          return respond(400, ContentTypes.text, Buffer.from("Unknown or missing operation\n"));
      }
    } catch (err) {
      const status = err instanceof ScepProtocolError ? 400 : 500;
      return respond(status, ContentTypes.text, Buffer.from(`${(err as Error).message}\n`));
    }
  }

  /** Fetch-API adapter (Deno, Bun, Cloudflare Workers, Next.js route handlers, Hono…). */
  fetchHandler = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const body = request.method === "POST" ? new Uint8Array(await request.arrayBuffer()) : undefined;
    const res = await this.handle({ method: request.method, query: url.searchParams, body });
    return new Response(res.body, { status: res.status, headers: res.headers });
  };

  /**
   * `node:http` / Express adapter. Mount it at the SCEP path. Works with a raw request stream
   * or with a body already read into a Buffer by middleware such as `express.raw()`.
   */
  nodeHandler(opts: { maxBodyBytes?: number } = {}): (req: IncomingMessage, res: ServerResponse) => void {
    const limit = opts.maxBodyBytes ?? 1024 * 1024;
    return (req, res) => {
      const dispatch = (body: Buffer) => {
        const url = new URL(req.url ?? "/", "http://localhost");
        this.handle({ method: req.method ?? "GET", query: url.searchParams, body })
          .then((r) => res.writeHead(r.status, { ...r.headers, "content-length": String(r.body.length) }).end(r.body))
          .catch(() => res.writeHead(500).end());
      };
      // Body already consumed by middleware (e.g. express.raw())?
      const parsed = (req as { body?: unknown }).body;
      if (parsed instanceof Uint8Array) return dispatch(toBuffer(parsed));
      const chunks: Buffer[] = [];
      let size = 0;
      let aborted = false;
      req.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > limit) {
          aborted = true;
          res.writeHead(413).end();
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", () => {
        if (!aborted) dispatch(Buffer.concat(chunks));
      });
    };
  }

  // -------------------------------------------------------------------------
  // Operations
  // -------------------------------------------------------------------------

  private getCACert(): ScepHttpResponse {
    if (!this.raCert && this.chain.length === 0) {
      return respond(200, ContentTypes.caCert, this.caCert.raw);
    }
    const certs = [this.caCert, ...(this.raCert ? [this.raCert] : []), ...this.chain];
    return respond(200, ContentTypes.caRaCert, createDegenerateSignedData(certs));
  }

  private getNextCACert(): ScepHttpResponse {
    if (!this.nextCa.length || !this.caKey) {
      return respond(404, ContentTypes.text, Buffer.from("No rollover certificate available\n"));
    }
    const body = createSignedData({
      content: createDegenerateSignedData(this.nextCa),
      signer: { certificate: this.caCert, privateKey: this.caKey, digestAlgorithm: "sha256" },
    });
    return respond(200, ContentTypes.nextCaCert, body);
  }

  /** Process a pkiMessage and return the DER CertRep. */
  async pkiOperation(der: Buffer): Promise<Buffer> {
    let message: PkiMessage;
    try {
      message = decodePkiMessage(der, { recipient: this.identity });
    } catch (err) {
      // Answer with a signed FAILURE where the request is identifiable (RFC 8894 §3.3.2).
      const peek = peekPkiMessage(der);
      if (!peek?.transactionId || !peek.senderNonce) throw err;
      const failInfo = err instanceof ScepProtocolError ? err.failInfo : FailInfo.badRequest;
      return this.certRep(
        { transactionId: peek.transactionId, senderNonce: peek.senderNonce, digestAlgorithm: "sha256" },
        { status: "failure", failInfo, failInfoText: (err as Error).message },
      );
    }

    const result = await this.dispatch(message).catch((err: unknown): ScepResult => {
      if (err instanceof ScepProtocolError) return { status: "failure", failInfo: err.failInfo, failInfoText: err.message };
      throw err;
    });
    return this.certRep(message, result);
  }

  private async dispatch(message: PkiMessage): Promise<ScepResult> {
    const { handler, maxClockSkewMs } = this.options;
    if (maxClockSkewMs !== undefined && message.signingTime) {
      if (Math.abs(message.signingTime.getTime() - Date.now()) > maxClockSkewMs) {
        return { status: "failure", failInfo: FailInfo.badTime };
      }
    }
    if (!message.messageData) {
      return { status: "failure", failInfo: FailInfo.badRequest, failInfoText: "Missing pkcsPKIEnvelope" };
    }
    const signer = message.signerCertificate;
    const ctx: ScepRequestContext = {
      message,
      transactionId: message.transactionId,
      signerCertificate: signer,
      selfSigned: isSelfSigned(signer),
      signerIssuedByCa: isIssuedBy(signer, this.caCert),
    };

    switch (message.messageType) {
      case MessageType.PKCSReq:
      case MessageType.RenewalReq: {
        const renewal = message.messageType === MessageType.RenewalReq;
        const csr = parseCsr(message.messageData);
        if (!csr.signatureValid) {
          return { status: "failure", failInfo: FailInfo.badMessageCheck, failInfoText: "Invalid CSR signature" };
        }
        if (ctx.selfSigned && !samePublicKey(signer.publicKey, csr.publicKey)) {
          return {
            status: "failure",
            failInfo: FailInfo.badMessageCheck,
            failInfoText: "Self-signed signer key does not match the CSR",
          };
        }
        if (renewal && !ctx.signerIssuedByCa) {
          return {
            status: "failure",
            failInfo: FailInfo.badRequest,
            failInfoText: "RenewalReq must be signed with a certificate issued by this CA",
          };
        }
        return handler.enroll({ ...ctx, csr, renewal });
      }
      case MessageType.CertPoll: {
        if (!handler.poll) return notSupported();
        const { issuer, subject } = decodeIssuerAndSubject(message.messageData);
        return handler.poll({ ...ctx, issuer, subject });
      }
      case MessageType.GetCert: {
        if (!handler.getCert) return notSupported();
        return handler.getCert({ ...ctx, ...decodeIssuerAndSerialNumber(message.messageData) });
      }
      case MessageType.GetCRL: {
        if (!handler.getCRL) return notSupported();
        return handler.getCRL({ ...ctx, ...decodeIssuerAndSerialNumber(message.messageData) });
      }
      default:
        return notSupported();
    }
  }

  private certRep(
    request: Pick<PkiMessage, "transactionId" | "senderNonce" | "digestAlgorithm"> &
      Partial<Pick<PkiMessage, "signerCertificate" | "encryptionAlgorithm">>,
    result: ScepResult,
  ): Buffer {
    const common = {
      messageType: MessageType.CertRep,
      transactionId: request.transactionId,
      recipientNonce: request.senderNonce,
      signer: this.identity,
      digestAlgorithm: request.digestAlgorithm as DigestAlgorithm,
    };
    if (result.status === "success") {
      if (!request.signerCertificate) throw new ScepError("Cannot encrypt CertRep without a requester certificate");
      const messageData = createDegenerateSignedData(
        (result.certificates ?? []).map(toCertificate),
        result.crls ?? [],
      );
      return encodePkiMessage({
        ...common,
        pkiStatus: PkiStatus.SUCCESS,
        messageData,
        recipient: request.signerCertificate,
        encryptionAlgorithm: request.encryptionAlgorithm ?? "aes-128-cbc",
      });
    }
    if (result.status === "pending") return encodePkiMessage({ ...common, pkiStatus: PkiStatus.PENDING });
    return encodePkiMessage({
      ...common,
      pkiStatus: PkiStatus.FAILURE,
      failInfo: result.failInfo ?? FailInfo.badRequest,
      failInfoText: result.failInfoText,
    });
  }
}

function notSupported(): ScepResult {
  return { status: "failure", failInfo: FailInfo.badRequest, failInfoText: "Operation not supported" };
}

function respond(status: number, contentType: string, body: Buffer): ScepHttpResponse {
  return { status, headers: { "content-type": contentType }, body };
}
