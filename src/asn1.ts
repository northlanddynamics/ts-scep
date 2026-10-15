/**
 * ASN.1 schemas that SCEP needs beyond what the @peculiar/asn1-* packages provide, plus
 * small helpers for building and reading attribute values.
 */
import * as asn1js from "asn1js";
import { AsnArray, AsnConvert, AsnProp, AsnPropTypes, AsnType, AsnTypeTypes } from "@peculiar/asn1-schema";
import { DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignerInfos } from "@peculiar/asn1-cms";
import { AlgorithmIdentifier, Name } from "@peculiar/asn1-x509";
import { ScepProtocolError } from "./errors.js";
import { FailInfo } from "./constants.js";
import { toArrayBuffer, toBuffer, type BytesLike } from "./util.js";

/** SET OF ANY — used for SignedData certificates and CRLs so that any encoding round-trips. */
@AsnType({ type: AsnTypeTypes.Set, itemType: AsnPropTypes.Any })
export class AnySet extends AsnArray<ArrayBuffer> {
  constructor(items?: ArrayBuffer[]) {
    super(items);
    Object.setPrototypeOf(this, AnySet.prototype);
  }
}

/**
 * CMS SignedData (RFC 5652 §5.1) with certificates and CRLs kept as raw DER. The upstream
 * schema cannot represent plain CRLs in RevocationInfoChoices, which SCEP's GetCRL relies on.
 */
export class ScepSignedData {
  @AsnProp({ type: AsnPropTypes.Integer })
  public version = 1;

  @AsnProp({ type: DigestAlgorithmIdentifiers })
  public digestAlgorithms = new DigestAlgorithmIdentifiers();

  @AsnProp({ type: EncapsulatedContentInfo })
  public encapContentInfo = new EncapsulatedContentInfo();

  @AsnProp({ type: AnySet, context: 0, implicit: true, optional: true })
  public certificates?: AnySet;

  @AsnProp({ type: AnySet, context: 1, implicit: true, optional: true })
  public crls?: AnySet;

  @AsnProp({ type: SignerInfos })
  public signerInfos = new SignerInfos();

  constructor(params: Partial<ScepSignedData> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```asn
 * IssuerAndSubject ::= SEQUENCE {
 *   issuer     Name,
 *   subject    Name }
 * ```
 * Message data of a CertPoll request (RFC 8894 §3.3.3).
 */
export class IssuerAndSubject {
  @AsnProp({ type: Name })
  public issuer = new Name();

  @AsnProp({ type: Name })
  public subject = new Name();

  constructor(params: Partial<IssuerAndSubject> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```asn
 * RSAES-OAEP-params ::= SEQUENCE {
 *   hashAlgorithm      [0] HashAlgorithm     DEFAULT sha1Identifier,
 *   maskGenAlgorithm   [1] MaskGenAlgorithm  DEFAULT mgf1SHA1Identifier,
 *   pSourceAlgorithm   [2] PSourceAlgorithm  DEFAULT pSpecifiedEmptyIdentifier }
 * ```
 * RFC 4055 §4.1. Defaulted fields are modelled as optional so that absent fields stay
 * distinguishable after parsing (the upstream schema substitutes a non-empty pSpecified label).
 */
export class OaepParams {
  @AsnProp({ type: AlgorithmIdentifier, context: 0, optional: true })
  public hashAlgorithm?: AlgorithmIdentifier;

  @AsnProp({ type: AlgorithmIdentifier, context: 1, optional: true })
  public maskGenAlgorithm?: AlgorithmIdentifier;

  @AsnProp({ type: AlgorithmIdentifier, context: 2, optional: true })
  public pSourceAlgorithm?: AlgorithmIdentifier;

  constructor(params: Partial<OaepParams> = {}) {
    Object.assign(this, params);
  }
}

export function printableString(value: string): ArrayBuffer {
  if (!/^[A-Za-z0-9 '()+,\-./:=?]*$/.test(value)) {
    throw new TypeError(`"${value}" contains characters not allowed in a PrintableString`);
  }
  return new asn1js.PrintableString({ value }).toBER(false);
}

export function utf8String(value: string): ArrayBuffer {
  return new asn1js.Utf8String({ value }).toBER(false);
}

export function octetString(value: BytesLike): ArrayBuffer {
  return new asn1js.OctetString({ valueHex: toArrayBuffer(value) }).toBER(false);
}

function parseBer(value: BytesLike): asn1js.AsnType {
  const parsed = asn1js.fromBER(toArrayBuffer(value));
  if (parsed.offset === -1) throw new ScepProtocolError("Malformed ASN.1 value", FailInfo.badRequest);
  return parsed.result;
}

export function objectIdentifier(oid: string): ArrayBuffer {
  return new asn1js.ObjectIdentifier({ value: oid }).toBER(false);
}

export function readObjectIdentifier(value: BytesLike): string {
  const node = parseBer(value);
  if (!(node instanceof asn1js.ObjectIdentifier)) {
    throw new ScepProtocolError("Expected an OBJECT IDENTIFIER value", FailInfo.badRequest);
  }
  return node.getValue();
}

/** Read any ASN.1 character string type (implementations are not uniform about the string type used). */
export function readString(value: BytesLike): string {
  const node = parseBer(value) as unknown as { getValue?: () => string };
  if (node instanceof asn1js.BaseStringBlock || typeof node.getValue === "function") {
    const v = node.getValue!();
    if (typeof v === "string") return v;
  }
  throw new ScepProtocolError("Expected an ASN.1 string value", FailInfo.badRequest);
}

/** Read an OCTET STRING (primitive or constructed). */
export function readOctetString(value: BytesLike): Buffer {
  const node = parseBer(value);
  if (!(node instanceof asn1js.OctetString)) {
    throw new ScepProtocolError("Expected an OCTET STRING value", FailInfo.badRequest);
  }
  return collectOctets(node);
}

function collectOctets(node: asn1js.OctetString): Buffer {
  if (!node.idBlock.isConstructed) return Buffer.from(node.valueBlock.valueHexView);
  const parts = (node.valueBlock.value as asn1js.OctetString[]).map(collectOctets);
  return Buffer.concat(parts);
}

/** DER-encode and sort a list of encoded SET OF elements, as DER requires. */
export function sortDerSet<T>(items: T[], encode: (item: T) => ArrayBuffer): T[] {
  return items
    .map((item) => ({ item, der: toBuffer(encode(item)) }))
    .sort((a, b) => Buffer.compare(a.der, b.der))
    .map((e) => e.item);
}

export function serialize(value: unknown): Buffer {
  return toBuffer(AsnConvert.serialize(value));
}

export function parse<T>(data: BytesLike, type: new () => T, what = type.name): T {
  try {
    return AsnConvert.parse(toArrayBuffer(data), type);
  } catch (err) {
    throw new ScepProtocolError(`Malformed ${what}`, FailInfo.badRequest, { cause: err });
  }
}
