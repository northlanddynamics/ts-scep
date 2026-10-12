import { describe, expect, it } from "vitest";
import {
  createCertificate,
  createCrl,
  createCsr,
  createDegenerateSignedData,
  createEnvelopedData,
  createSelfSignedCertificate,
  createSignedData,
  generateRsaKeyPair,
  nameToString,
  openEnvelopedData,
  parseCsr,
  parseSignedData,
  verifySignerInfo,
  buildName,
  encodeName,
  type EncryptionAlgorithm,
} from "../src/index.js";
import { hasOpenSsl, makeCa, openssl, pemKey } from "./helpers.js";

const ossl = hasOpenSsl();
const content = Buffer.from("The quick brown fox jumps over the lazy dog");

describe("names", () => {
  it("parses RFC 4514 and OpenSSL style names to the same encoding", () => {
    const a = encodeName("CN=device\\, one,O=Example,C=US");
    const b = encodeName("/C=US/O=Example/CN=device, one");
    const c = encodeName([["C", "US"], ["O", "Example"], ["CN", "device, one"]]);
    expect(a).toEqual(b);
    expect(a).toEqual(c);
    expect(nameToString(a)).toBe("CN=device\\, one,O=Example,C=US");
    expect(nameToString(buildName("CN=a+UID=b,DC=example,DC=com"))).toBe("CN=a+UID=b,DC=example,DC=com");
  });
});

describe("certificates, CSRs and CRLs", () => {
  it("creates certificates node can parse and verify", () => {
    const ca = makeCa();
    const { privateKey } = generateRsaKeyPair();
    const cert = createCertificate({
      subject: "CN=leaf",
      publicKey: privateKey,
      signingKey: ca.privateKey,
      issuer: ca.certificate,
      subjectAltNames: { dns: ["leaf.example.com"], ip: ["10.0.0.1"] },
      extendedKeyUsage: ["1.3.6.1.5.5.7.3.2"],
    });
    expect(cert.subject).toBe("CN=leaf");
    expect(cert.checkIssued(ca.certificate)).toBe(true);
    expect(cert.verify(ca.certificate.publicKey)).toBe(true);
    expect(cert.subjectAltName).toContain("DNS:leaf.example.com");
    expect(ca.certificate.ca).toBe(true);
  });

  it("creates CSRs with challengePassword and extensions", () => {
    const { privateKey } = generateRsaKeyPair();
    const der = createCsr({
      subject: "CN=device-1,O=Example",
      privateKey,
      challengePassword: "s3cret",
      subjectAltNames: { dns: ["device-1.example.com"] },
    });
    const csr = parseCsr(der);
    expect(csr.signatureValid).toBe(true);
    expect(csr.challengePassword).toBe("s3cret");
    expect(csr.subjectString).toBe("CN=device-1,O=Example");
    expect(csr.extensions).toHaveLength(1);
    if (ossl) {
      const { stdout } = openssl(["req", "-in", "req.der", "-inform", "DER", "-verify", "-noout", "-text"], { "req.der": der });
      expect(stdout.toString()).toContain("challengePassword");
      expect(stdout.toString()).toContain("device-1.example.com");
    }
  });

  it.runIf(ossl)("creates CRLs OpenSSL accepts", () => {
    const ca = makeCa();
    const crl = createCrl({
      issuer: ca.certificate,
      signingKey: ca.privateKey,
      revoked: [{ serialNumber: Buffer.from([0x01, 0x02]) }],
    });
    const { stdout } = openssl(
      ["crl", "-in", "crl.der", "-inform", "DER", "-CAfile", "ca.pem", "-noout", "-text"],
      { "crl.der": crl, "ca.pem": ca.certificate.toString() },
    );
    expect(stdout.toString()).toContain("Serial Number: 0102");
  });
});

describe("SignedData", () => {
  it("round-trips and verifies", () => {
    const { privateKey } = generateRsaKeyPair();
    const certificate = createSelfSignedCertificate({ subject: "CN=signer", privateKey });
    const der = createSignedData({
      content,
      signer: { certificate, privateKey, digestAlgorithm: "sha256" },
    });
    const sd = parseSignedData(der);
    expect(sd.content).toEqual(content);
    const v = verifySignerInfo(sd, sd.signerInfos[0]!);
    expect(v.certificate.raw).toEqual(certificate.raw);
    expect(v.signingTime).toBeInstanceOf(Date);
  });

  it("detects tampering", () => {
    const { privateKey } = generateRsaKeyPair();
    const certificate = createSelfSignedCertificate({ subject: "CN=signer", privateKey });
    const der = createSignedData({ content, signer: { certificate, privateKey, digestAlgorithm: "sha256" } });
    const idx = der.indexOf(content);
    der[idx] ^= 0xff;
    const sd = parseSignedData(der);
    expect(() => verifySignerInfo(sd, sd.signerInfos[0]!)).toThrow(/messageDigest/);
  });

  it.runIf(ossl)("is verified by OpenSSL", () => {
    const { privateKey } = generateRsaKeyPair();
    const certificate = createSelfSignedCertificate({ subject: "CN=signer", privateKey });
    for (const digestAlgorithm of ["sha1", "sha256", "sha512"] as const) {
      const der = createSignedData({ content, signer: { certificate, privateKey, digestAlgorithm } });
      const { stdout } = openssl(["cms", "-verify", "-inform", "DER", "-in", "sd.der", "-noverify"], { "sd.der": der });
      expect(stdout).toEqual(content);
    }
  });

  it.runIf(ossl)("verifies OpenSSL-produced SignedData", () => {
    const { privateKey } = generateRsaKeyPair();
    const certificate = createSelfSignedCertificate({ subject: "CN=signer", privateKey });
    const { files } = openssl(
      ["cms", "-sign", "-nodetach", "-binary", "-in", "c.bin", "-signer", "c.pem", "-inkey", "k.pem", "-outform", "DER", "-out", "o.der", "-md", "sha256"],
      { "c.bin": content, "c.pem": certificate.toString(), "k.pem": pemKey(privateKey) },
      ["o.der"],
    );
    const sd = parseSignedData(files["o.der"]!);
    expect(sd.content).toEqual(content);
    expect(verifySignerInfo(sd, sd.signerInfos[0]!).certificate.raw).toEqual(certificate.raw);
  });

  it.runIf(ossl)("produces degenerate certs-only structures OpenSSL can read", () => {
    const ca = makeCa();
    const crl = createCrl({ issuer: ca.certificate, signingKey: ca.privateKey });
    const der = createDegenerateSignedData([ca.certificate], [crl]);
    const { stdout } = openssl(["pkcs7", "-inform", "DER", "-in", "p.der", "-print_certs", "-noout"], { "p.der": der });
    expect(stdout.toString()).toContain("Test Root CA");
    const sd = parseSignedData(der);
    expect(sd.certificates).toHaveLength(1);
    expect(sd.crls[0]).toEqual(crl);
  });
});

describe("EnvelopedData", () => {
  const { privateKey } = generateRsaKeyPair();
  const certificate = createSelfSignedCertificate({ subject: "CN=recipient", privateKey });
  const algs: EncryptionAlgorithm[] = ["aes-128-cbc", "aes-192-cbc", "aes-256-cbc", "des-ede3-cbc", "des-cbc"];

  it.each(algs)("round-trips with %s", (alg) => {
    const env = createEnvelopedData(content, certificate, alg);
    const opened = openEnvelopedData(env, certificate, privateKey);
    expect(opened.content).toEqual(content);
    expect(opened.algorithm).toBe(alg);
  });

  // OpenSSL 3 only provides single DES via its legacy provider.
  it.runIf(ossl).each(algs.filter((a) => a !== "des-cbc"))("is decrypted by OpenSSL (%s)", (alg) => {
    const env = createEnvelopedData(content, certificate, alg);
    const { stdout } = openssl(
      ["cms", "-decrypt", "-inform", "DER", "-in", "e.der", "-recip", "c.pem", "-inkey", "k.pem"],
      { "e.der": env, "c.pem": certificate.toString(), "k.pem": pemKey(privateKey) },
    );
    expect(stdout).toEqual(content);
  });

  it.runIf(ossl).each([
    ["-aes128", "aes-128-cbc"],
    ["-aes256", "aes-256-cbc"],
    ["-des3", "des-ede3-cbc"],
  ])("decrypts OpenSSL output (%s)", (flag, alg) => {
    const { files } = openssl(
      ["cms", "-encrypt", "-binary", flag!, "-in", "c.bin", "-outform", "DER", "-out", "e.der", "c.pem"],
      { "c.bin": content, "c.pem": certificate.toString() },
      ["e.der"],
    );
    const opened = openEnvelopedData(files["e.der"]!, certificate, privateKey);
    expect(opened.content).toEqual(content);
    expect(opened.algorithm).toBe(alg);
  });

  it("rejects a wrong key", () => {
    const other = generateRsaKeyPair().privateKey;
    const env = createEnvelopedData(content, certificate, "aes-128-cbc");
    expect(() => openEnvelopedData(env, certificate, other)).toThrow();
  });
});

