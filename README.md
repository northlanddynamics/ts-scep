# ts-scep

A TypeScript SDK for the **Simple Certificate Enrolment Protocol (SCEP)**, as specified in
[RFC 8894](https://www.rfc-editor.org/rfc/rfc8894). It covers both sides of the protocol:

- **Client:** CA discovery, enrolment, renewal, polling for manual approval, and certificate and CRL retrieval.
- **Server (CA / RA):** a framework-agnostic request handler. Issuance decisions are delegated to your code.
- **Building blocks:** pkiMessage encoding and decoding, the CMS SignedData and EnvelopedData it needs, PKCS #10 requests, X.509 certificates and CRLs.

It has been tested against OpenSSL, the [sscep](https://github.com/certnanny/sscep) C client, and the
[micromdm/scep](https://github.com/micromdm/scep) Go server (see [Testing](#testing)).

```sh
npm install ts-scep
```

You need Node.js 20 or later, or Bun 1.4 or later. The SDK uses `node:crypto`, because WebCrypto can't do
RSA PKCS #1 v1.5 key transport or 3DES, and SCEP depends on both. Runtimes that only offer WebCrypto
(browsers, Cloudflare Workers) are not supported.

---

## Contents

- [SCEP in brief (RFC 8894)](#scep-in-brief-rfc-8894)
- [Client usage](#client-usage)
- [Server usage](#server-usage)
  - [Bun and Hono](#bun-and-hono)
- [Low-level API](#low-level-api)
- [Security notes](#security-notes)
- [Testing](#testing)
- [Limitations](#limitations)

---

## SCEP in brief (RFC 8894)

SCEP lets a device get an X.509 certificate from a CA over plain HTTP. It authenticates the request with
a shared secret (the PKCS #9 `challengePassword` in the CSR) or with an existing certificate. RFC 8894
(September 2020, Informational) is the first RFC to document the protocol. It replaces a long series of
Internet-Drafts (`draft-nourse-scep`, `draft-gutmann-scep`). The RFC also modernises the algorithms
(AES and SHA-2) and adds the `SCEPStandard` capability.

### Transport (§4)

Every request goes to a single URL, conventionally `/cgi-bin/pkiclient.exe`. The query string
carries `operation=<name>` and, where needed, `message=<value>`.

| Operation       | Method              | Request `message`             | Response content type                                                    |
|-----------------|---------------------|-------------------------------|--------------------------------------------------------------------------|
| `GetCACaps`     | GET                 | optional CA identifier        | `text/plain`, one capability per line                                    |
| `GetCACert`     | GET                 | optional CA identifier        | `application/x-x509-ca-cert` (one DER cert) or `application/x-x509-ca-ra-cert` (certs-only CMS) |
| `GetNextCACert` | GET                 | optional CA identifier        | `application/x-x509-next-ca-cert`: CMS SignedData, signed by the current CA |
| `PKIOperation`  | POST (or GET)       | pkiMessage (body, or base64 in the query) | `application/x-pki-message`                                     |

POST is used when the CA advertises `POSTPKIOperation` or `SCEPStandard`. Otherwise the DER message is
base64-encoded and URL-encoded into the query string.

### Capabilities (§3.5.2)

`AES`, `DES3`, `GetNextCACert`, `POSTPKIOperation`, `Renewal`, `SHA-1`, `SHA-256`, `SHA-512`,
`SCEPStandard`. Matching is case-insensitive. `SCEPStandard` implies `AES`, `POSTPKIOperation` and
`SHA-256`. If a server has no `GetCACaps`, the client should assume the minimal legacy behaviour.

### pkiMessage structure (§3)

```
ContentInfo { SignedData {
  encapContentInfo: id-data, eContent = pkcsPKIEnvelope     -- omitted on CertRep FAILURE / PENDING
                     └─ ContentInfo { EnvelopedData {         -- RSA key transport to the recipient
                          encryptedContent = messageData } }  -- rsaEncryption or RSAES-OAEP
  certificates: signer certificate (self-signed on first enrolment)
  signerInfo.signedAttrs:
    transactionID   2.16.840.1.113733.1.9.7   PrintableString
    messageType     2.16.840.1.113733.1.9.2   PrintableString (decimal)
    senderNonce     2.16.840.1.113733.1.9.5   OCTET STRING (16 random bytes)
    recipientNonce  2.16.840.1.113733.1.9.6   OCTET STRING (CertRep: echoes the request senderNonce)
    pkiStatus       2.16.840.1.113733.1.9.3   PrintableString (CertRep)
    failInfo        2.16.840.1.113733.1.9.4   PrintableString (CertRep FAILURE)
    failInfoText    1.3.6.1.5.5.7.24.1        UTF8String      (optional, CertRep FAILURE)
    contentType, messageDigest, [signingTime]
}}
```

| messageType  | Value | messageData                              | Signed by                      |
|--------------|-------|------------------------------------------|--------------------------------|
| `CertRep`    | 3     | certs-only SignedData (certs and/or CRL) | CA or RA                       |
| `RenewalReq` | 17    | PKCS #10 request                         | existing CA-issued certificate |
| `PKCSReq`    | 19    | PKCS #10 request                         | self-signed (or existing) cert |
| `CertPoll`   | 20    | `IssuerAndSubject` (formerly GetCertInitial) | same signer as the request |
| `GetCert`    | 21    | `IssuerAndSerialNumber`                  | requester certificate          |
| `GetCRL`     | 22    | `IssuerAndSerialNumber` of the cert being checked | requester certificate |

- **pkiStatus:** `SUCCESS` = 0, `FAILURE` = 2, `PENDING` = 3.
- **failInfo:** `badAlg` = 0, `badMessageCheck` = 1, `badRequest` = 2, `badTime` = 3, `badCertId` = 4.

On a first enrolment the client signs with a temporary **self-signed certificate** for the key it
wants certified. The CA encrypts the CertRep to that same certificate. A `PENDING` reply means the
request is waiting for manual approval. The client then sends `CertPoll` with the same transactionID
until it gets `SUCCESS` or `FAILURE`. Where an **RA** sits in front of the CA, `GetCACert` returns both
certificates. Requests are encrypted to the RA's key-encipherment certificate, and replies are signed
by the RA.

---

## Client usage

```ts
import { PkiStatus, ScepClient, ScepFailureError, createCsr, generateRsaKeyPair } from "ts-scep";

const client = new ScepClient({
  url: "http://ca.example.com/cgi-bin/pkiclient.exe",
  // Verify the CA out of band. GetCACert itself is unauthenticated.
  caFingerprint: "98:75:C4:6A:…",
});

const { privateKey } = generateRsaKeyPair(2048);
const csr = createCsr({
  subject: "CN=device-01,O=Example",
  privateKey,
  challengePassword: "one-time-secret",
  subjectAltNames: { dns: ["device-01.example.com"] },
});

try {
  let result = await client.enroll({ csr, privateKey });
  if (result.status === PkiStatus.PENDING) {
    // Manual approval: poll with CertPoll until the CA decides.
    result = await client.waitForCertificate(result.pending, { intervalMs: 60_000, timeoutMs: 86_400_000 });
  }
  console.log(result.certificate.toString()); // X509Certificate (node:crypto)
} catch (err) {
  if (err instanceof ScepFailureError) console.error(err.failInfo, err.failInfoText);
  else throw err;
}
```

The client negotiates algorithms and transport from `GetCACaps`. With `SCEPStandard` or `AES` it uses
AES-128-CBC, otherwise 3DES. It prefers SHA-256, then SHA-512, then SHA-1. It uses POST when
`POSTPKIOperation` or `SCEPStandard` is advertised. You can override any of these with
`encryptionAlgorithm`, `digestAlgorithm` or `usePost`.

The content-encryption key is wrapped with RSAES-PKCS1-v1_5 by default. To use RSAES-OAEP, set
`keyTransport` to `"rsa-oaep"` (SHA-256) or to `{ scheme: "rsa-oaep", hash, label }`. RFC 8894 has no
capability keyword for OAEP, so the client can't detect support. Only enable it for CAs you know accept
it: many deployed SCEP servers, including micromdm/scep and older NDES, only handle PKCS #1 v1.5.

Every CertRep is checked before it's accepted:

- The signature must verify.
- The signer must be the CA, an RA in the GetCACert set, or a certificate the CA issued.
- `transactionID` must match the request.
- `recipientNonce` must equal the request's `senderNonce`.

### Other operations

```ts
await client.getCACaps();              // CACapabilities: .has("AES"), .supportsRenewal, …
await client.getCACert();              // CACertificates: .ca, .ra, .encryptionCertificate, .signingCertificate
await client.getNextCACert();          // rollover certificates, verified against the current CA

// Renewal (RenewalReq) or re-enrolment, signed with the current certificate:
await client.enroll({ csr: newCsr, privateKey: newKey, signer: { certificate: current, privateKey: currentKey } });

await client.poll(pending);            // a single CertPoll
await client.getCert({ serialNumber, signer: { certificate, privateKey } });
await client.getCRL({ signer: { certificate, privateKey } }); // DER-encoded CRL
```

`ScepClientOptions` also accepts:

- `caIdentifier`: the `message` parameter for multi-CA servers.
- `caCertificates` and `capabilities`: pre-provisioned values that skip discovery.
- `headers`, `timeoutMs`, and a custom `fetch`.

---

## Server usage

`ScepServer` handles the protocol: message parsing, signature verification, decryption, CSR checks,
nonce and transaction handling, and building the CertRep. Your `ScepHandler` decides what to issue.

```ts
import { createServer } from "node:http";
import { FailInfo, ScepServer, createCertificate } from "ts-scep";

const scep = new ScepServer({
  ca: { certificate: caCert, privateKey: caKey },   // or add `ra: { certificate, privateKey }`
  maxClockSkewMs: 10 * 60_000,                      // optional: badTime check on signingTime
  handler: {
    async enroll(req) {
      // req.csr: subject, publicKey, challengePassword, extensions (signature already verified)
      // req.renewal, req.selfSigned, req.signerIssuedByCa, req.transactionId, req.message
      const ok = req.renewal ? req.signerIssuedByCa : await checkChallenge(req.csr.challengePassword);
      if (!ok) return { status: "failure", failInfo: FailInfo.badRequest, failInfoText: "Not authorised" };
      if (await needsApproval(req)) return { status: "pending" };   // the client will send CertPoll
      const cert = createCertificate({
        subject: req.csr.subject, publicKey: req.csr.publicKey,
        signingKey: caKey, issuer: caCert, extensions: req.csr.extensions,
      });
      return { status: "success", certificates: [cert] };
    },
    poll: (req) => /* look up req.transactionId */ ({ status: "pending" }),
    getCert: (req) => /* req.issuer, req.serialNumber */ ({ status: "failure", failInfo: FailInfo.badCertId }),
    getCRL: (req) => ({ status: "success", crls: [currentCrlDer] }),
  },
});

createServer(scep.nodeHandler()).listen(8080);    // node:http or Express (also accepts express.raw())
// export default { fetch: scep.fetchHandler };   // Fetch-API runtimes (Bun, Hono, …), see below
// await scep.handle({ method, query, body });    // any other framework
```

Before your handler runs, the server checks that:

- The CSR signature is valid.
- A self-signed signer uses the CSR's key.
- A `RenewalReq` is signed by a certificate this CA issued.

CertRep envelopes use the key-transport scheme of the request, so an OAEP client gets an OAEP reply
and every other client gets PKCS #1 v1.5. Set `keyTransport` to a fixed scheme to override this, and
`requireOaep: true` to reject PKCS #1 v1.5 requests with `badAlg`.

If a request fails verification or decryption, the server returns a signed `FAILURE` CertRep
(`badMessageCheck`, `badAlg`, and so on) when it can identify the request. Otherwise it returns HTTP 400.

POST bodies larger than `maxBodyBytes` (default 1 MiB) get HTTP 413 from `nodeHandler` and `fetchHandler`.

A runnable example CA is in [`examples/server.ts`](examples/server.ts), and the same CA on Hono and Bun is in
[`examples/server-hono.ts`](examples/server-hono.ts). A client example is in [`examples/enroll.ts`](examples/enroll.ts).

### Bun and Hono

`fetchHandler` is a bound `(Request) => Promise<Response>`, so it can be handed straight to `Bun.serve` or
to a Hono route. The handler ignores the path, so mount it wherever your clients expect it:

```ts
import { Hono } from "hono";

const app = new Hono();
app.all("/scep", (c) => scep.fetchHandler(c.req.raw));
app.all("/cgi-bin/pkiclient.exe", (c) => scep.fetchHandler(c.req.raw));

export default { port: 8080, fetch: app.fetch };   // bun run server.ts
```

`fetchHandler` reads the request body itself and enforces `maxBodyBytes`, while the body streams in as well as
from `Content-Length`. Mount it before any middleware that reads the body. If middleware has already read it
(Hono's `bodyLimit`, logging, signature checks), the stream is spent, so pass the bytes instead:

```ts
import { bodyLimit } from "hono/body-limit";

app.all("/scep", bodyLimit({ maxSize: 256 * 1024 }), async (c) =>
  scep.handleFetch(c.req.raw, { body: new Uint8Array(await c.req.arrayBuffer()) }),
);
```

`Bun.serve` accepts bodies of up to 128 MB by default. `maxBodyBytes` stops SCEP from buffering more than it
needs, but you can also lower `maxRequestBodySize` in `Bun.serve`.

Install the published package, which ships compiled JavaScript. If you import the TypeScript sources directly
(a workspace or git dependency), enable `"experimentalDecorators": true` and `"useDefineForClassFields": false`
in your tsconfig, because the ASN.1 schema library uses legacy decorators. Without them, Bun fails when it
loads the module.

---

## Low-level API

Everything the client and server use is exported:

| Area          | Exports |
|---------------|---------|
| pkiMessage    | `encodePkiMessage`, `decodePkiMessage`, `peekPkiMessage`, `encodeIssuerAndSubject`, `encodeIssuerAndSerialNumber`, `decode…`, `transactionIdFromPublicKey`, `randomTransactionId` |
| CMS           | `createSignedData`, `parseSignedData`, `verifySignerInfo`, `createDegenerateSignedData`, `createEnvelopedData`, `openEnvelopedData` |
| X.509 / PKCS #10 | `createCsr`, `parseCsr`, `createCertificate`, `createSelfSignedCertificate`, `createCrl`, `buildName`, `encodeName`, `nameToString`, `isSelfSigned`, `isIssuedBy` |
| Constants     | `MessageType`, `PkiStatus`, `FailInfo`, `Capability`, `Operation`, `ContentTypes`, `OID` |
| Errors        | `ScepError`, `ScepProtocolError` (carries `failInfo`), `ScepFailureError`, `ScepHttpError` |

Keys can be passed as `KeyObject`s, PEM or DER. Certificates can be `X509Certificate`s, PEM or DER. Names
can be RFC 4514 strings (`"CN=x,O=y"`), OpenSSL-style strings (`"/O=y/CN=x"`), `[type, value]` pairs, or
DER.

---

## Security notes

- **Pin the CA.** `GetCACert` travels over unauthenticated HTTP. Pass `caFingerprint`, or pre-provision
  `caCertificates`, as RFC 8894 §2.2 requires.
- **Treat the challenge password as a one-time secret.** It is only protected by the pkcsPKIEnvelope
  encryption. Compare it in constant time on the server.
- SCEP gives no proof that a request is fresh. If replay matters, enable `maxClockSkewMs` and track
  transaction IDs in your handler.
- RSAES-OAEP is supported for key transport (see `keyTransport`). OAEP decoding failures are also
  replaced by a random key, so they surface as ordinary content-decryption errors.
- RSA PKCS #1 v1.5 decryption uses implicit rejection (draft-irtf-cfrg-rsa-guidance): a malformed
  ciphertext deterministically decrypts to a synthetic key, so padding errors can't be told apart from
  content-decryption errors (Bleichenbacher / Marvin). Node.js on OpenSSL 3.2+ does this natively. On Bun,
  and on Node builds that refuse PKCS #1 v1.5 decryption, the SDK performs raw RSA and runs the same
  algorithm in branch-free JavaScript, with output identical to OpenSSL's. JavaScript gives no hard
  constant-time guarantees. If every client in your fleet supports OAEP, set `requireOaep: true`.
- DES and SHA-1 are only used when a peer requires them. Single DES is never picked automatically.

---

## Testing

```sh
npm test            # unit + end-to-end tests (OpenSSL interop runs if `openssl` is on PATH)
npm run test:bun    # the same suite with Bun as the runtime (Hono tests use Bun.serve)
npm run typecheck
npm run build
```

Interoperability suites run against independent implementations when you supply the binaries:

```sh
# sscep (C client) → ts-scep ScepServer: getcaps, getca, enroll (AES/3DES, SHA-1/256/512),
# manual approval polling, getcert, getcrl, re-enrolment
SSCEP_BIN=/path/to/sscep npm test

# ts-scep ScepClient → micromdm/scep (Go server): POST/GET enrolment, DES/3DES, rejection, re-enrolment
SCEPSERVER_BIN=/path/to/scepserver npm test
```

The CI workflow builds both tools and runs these suites on Node.js and on Bun.

---

## Limitations

- **Key types.** SCEP's key transport needs RSA, so requester and CA/RA encryption keys must be RSA.
  ECDSA signatures can be verified, but not used for enrolment.
- **Recipient and cipher support.** Only key-transport recipients are supported (`rsaEncryption` and
  `id-RSAES-OAEP` with SHA-1/256/384/512). OAEP parameters with a different MGF1 hash than the OAEP
  hash are rejected, because Node.js can't express them. Key agreement, RC2 and Blowfish are not supported.
- **Runtime.** The SDK runs on Node.js (≥ 20) and Bun (≥ 1.4, the version CI tests). It does not run in
  browsers or WebCrypto-only runtimes such as Cloudflare Workers.

## License

MIT
