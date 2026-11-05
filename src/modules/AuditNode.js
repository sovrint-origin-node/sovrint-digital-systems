/**
 * SOVRINT™ AuditNode — synthetic ONYX receipt verification boundary.
 * Copyright (c) 2026 Katrina Pietroniro. All rights reserved.
 * This module does not validate historical facts, certify evidence, or provide independent custody.
 * No secret material, external service, or network access is required.
 */
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';

const HEX64 = /^[0-9a-f]{64}$/;
const OBJECT_KEY = /^[A-Za-z0-9_]+$/;
const QUEUE_NAME = 'sovrint-onyx-admissions-private-v1';
const CUSTODY = 'CLOUDFLARE_ACCOUNT_CONTROLLED_STAGING_NOT_INDEPENDENT_CUSTODY';
const RECORD_SCHEMA = 'sovrint-onyx-remote-admission-v1';
const REQ_SCHEMA = 'sovrint-onyx-witness-admission-request-v1';
const RECEIPT_SCHEMA = 'sovrint-onyx-remote-witness-receipt-v1';
const BYTES_LIMIT = 64 * 1024;

function isPlain(value) {
  return value !== null && typeof value === 'object' &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
function fail(reason) {
  return Object.freeze({verified: false, distortionNeutralized: false, reason, classification: 'UNVERIFIED'});
}
function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}
function assertHex64(value) { return typeof value === 'string' && HEX64.test(value); }
function assertB64(value) {
  if (typeof value !== 'string' || value.length !== 88 || !/^[A-Za-z0-9+/]{86}==$/.test(value))
    throw new Error('INVALID_SIGNATURE_ENCODING');
  const bin = Buffer.from(value, 'base64');
  if (bin.length !== 64 || bin.toString('base64') !== value) throw new Error('INVALID_SIGNATURE_ENCODING');
  return bin;
}
function canonicalValue(value, depth=0) {
  if (depth > 16) throw new Error('INVALID_CANONICAL_STRUCTURE');
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number' && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(x=>canonicalValue(x, depth+1)).join(',') + ']';
  if (!isPlain(value)) throw new Error('INVALID_CANONICAL_STRUCTURE');
  const names = Object.keys(value).sort();
  if (names.some(name=>!OBJECT_KEY.test(name))) throw new Error('INVALID_CANONICAL_STRUCTURE');
  return '{' + names.map(name=> {
    const d = Object.getOwnPropertyDescriptor(value, name);
    if (!d || !('value' in d)) throw new Error('INVALID_CANONICAL_STRUCTURE');
    return JSON.stringify(name) + ':' + canonicalValue(d.value, depth+1);
  }).join(',') + '}';
}
function canonical(value) {
  const data = Buffer.from(canonicalValue(value) + '\n','utf8');
  if (data.length > BYTES_LIMIT) throw new Error('RECEIPT_TOO_LARGE');
  return data;
}
function exactFields(obj, fields) {
  return isPlain(obj) && Object.keys(obj).length === fields.length &&
    fields.every(k=>Object.prototype.hasOwnProperty.call(obj,k));
}
function assertPem(pem, expectedPin) {
  if (typeof pem !== 'string' || pem.length > 2000 || sha256(Buffer.from(pem,'utf8')) !== expectedPin)
    throw new Error('UNTRUSTED_PUBLIC_KEY');
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('UNTRUSTED_PUBLIC_KEY');
  return key;
}

/**
 * Validate a cryptographic record against independently supplied trusted hashes and witness PEM.
 * The trust object MUST come from a separately controlled source, never from record fields.
 * No successful result represents verification of factual claims or legal evidence.
 */
export function verifyOnyxReceipt(record, trust) {
  try {
    const required = ['expectedAnchorSha256','expectedReceiptSha256','expectedRecordSha256',
      'originPublicKeySha256','witnessPublicKeySha256','witnessPublicKeyPem'];
    if (!isPlain(trust) || required.some(k=>typeof trust[k] !== 'string') ||
      required.slice(0,5).some(k=>!assertHex64(trust[k]))) return fail('TRUST_ANCHORS_REQUIRED');
    if (!exactFields(record,['schema','request','server_attestation']) || record.schema !== RECORD_SCHEMA)
      return fail('RECORD_SCHEMA_INVALID');
    const req=record.request, signed=record.server_attestation;
    if (!isPlain(req) || !exactFields(signed,['receipt','canonical_receipt_sha256','signature_algorithm','signature_base64','witness_key_pem_sha256']))
      return fail('RECORD_SCHEMA_INVALID');
    const receipt=signed.receipt;
    if (!isPlain(req.anchor) || !isPlain(receipt) || req.schema !== REQ_SCHEMA || receipt.schema !== RECEIPT_SCHEMA)
      return fail('RECORD_SCHEMA_INVALID');
    if (req.classification !== 'PRIVATE_SYNTHETIC_ONLY' || req.contains_original_evidence !== false ||
      req.contains_private_key !== false || receipt.classification !== 'PRIVATE_SYNTHETIC_ONLY')
      return fail('UNSAFE_CLASSIFICATION');
    if (req.signature_algorithm !== 'Ed25519' || signed.signature_algorithm !== 'Ed25519')
      return fail('SIGNATURE_ALGORITHM_INVALID');
    if (receipt.queue_name !== QUEUE_NAME || receipt.custody !== CUSTODY ||
      receipt.transport !== 'PRIVATE_CLOUDFLARE_QUEUE_ACCOUNT_API_NOT_ACCESS_JWT')
      return fail('RECEIPT_CONTEXT_INVALID');
    if (req.signer_public_key_sha256 !== trust.originPublicKeySha256 ||
      signed.witness_key_pem_sha256 !== trust.witnessPublicKeySha256 ||
      req.anchor.public_key_sha256 !== trust.originPublicKeySha256)
      return fail('PUBLIC_KEY_PIN_MISMATCH');
    if (req.anchor_canonical_sha256 !== trust.expectedAnchorSha256 ||
      signed.canonical_receipt_sha256 !== trust.expectedReceiptSha256 ||
      receipt.anchor_canonical_sha256 !== req.anchor_canonical_sha256 ||
      receipt.chain_head !== req.anchor.chain_head)
      return fail('HASH_LINK_MISMATCH');
    const recordBytes=canonical(record), originBytes=canonical(req.anchor), receiptBytes=canonical(receipt);
    if (sha256(recordBytes) !== trust.expectedRecordSha256 ||
      sha256(originBytes) !== trust.expectedAnchorSha256 ||
      sha256(receiptBytes) !== trust.expectedReceiptSha256)
      return fail('DIGEST_MISMATCH');
    const originKey=assertPem(req.signer_public_key_pem, trust.originPublicKeySha256);
    const witnessKey=assertPem(trust.witnessPublicKeyPem, trust.witnessPublicKeySha256);
    const originOK=verifySignature(null,originBytes,originKey,assertB64(req.anchor_signature_base64));
    const witnessOK=verifySignature(null,receiptBytes,witnessKey,assertB64(signed.signature_base64));
    if (!originOK || !witnessOK) return fail('SIGNATURE_INVALID');
    return Object.freeze({
      verified: true,
      distortionNeutralized: false,
      classification: 'CRYPTOGRAPHIC_RECORD_VERIFIED_SYNTHETIC_ONLY',
      reason: 'SIGNATURES_AND_DIGESTS_VERIFIED',
      anchorSha256: trust.expectedAnchorSha256,
      receiptSha256: trust.expectedReceiptSha256,
      recordSha256: trust.expectedRecordSha256,
      custody: CUSTODY
    });
  } catch {
    return fail('RECEIPT_VERIFICATION_FAILED');
  }
}

/** Legacy API is synchronous and deliberately fail-closed for text/untrusted inputs. */
export function AuditNode(record, trust) {
  if (!isPlain(record) || !isPlain(trust)) return fail('UNVERIFIED_INPUT');
  return verifyOnyxReceipt(record, trust);
}