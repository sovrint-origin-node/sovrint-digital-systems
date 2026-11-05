import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, generateKeyPairSync, sign} from 'node:crypto';
import {AuditNode, verifyOnyxReceipt} from '../src/modules/AuditNode.js';

const hash = value=>createHash('sha256').update(value).digest('hex');
const canon = obj=>{
 const f=x=>x===null?'null':Array.isArray(x)?'['+x.map(f).join(',')+']':typeof x==='object'?'{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+f(x[k])).join(',')+'}':JSON.stringify(x);
 return Buffer.from(f(obj)+'\n','utf8');
};
function fixture(){
 const origin=generateKeyPairSync('ed25519');const witness=generateKeyPairSync('ed25519');
 const pub1=origin.publicKey.export({type:'spki',format:'pem'}),pub2=witness.publicKey.export({type:'spki',format:'pem'});
 const pin1=hash(pub1),pin2=hash(pub2);
 const anchor={schema:'sovrint-onyx-synthetic-anchor-v1',created_at_utc:'2026-11-04T15:00:00.123456+00:00',chain_head:'a'.repeat(64),public_key_sha256:pin1,classification:'PRIVATE_SYNTHETIC_ONLY'};
 const anchorHash=hash(canon(anchor));
 const req={schema:'sovrint-onyx-witness-admission-request-v1',classification:'PRIVATE_SYNTHETIC_ONLY',contains_original_evidence:false,contains_private_key:false,signature_algorithm:'Ed25519',anchor,anchor_canonical_sha256:anchorHash,anchor_signature_base64:sign(null,canon(anchor),origin.privateKey).toString('base64'),signer_public_key_pem:pub1,signer_public_key_sha256:pin1};
 const receipt={schema:'sovrint-onyx-remote-witness-receipt-v1',classification:'PRIVATE_SYNTHETIC_ONLY',custody:'CLOUDFLARE_ACCOUNT_CONTROLLED_STAGING_NOT_INDEPENDENT_CUSTODY',transport:'PRIVATE_CLOUDFLARE_QUEUE_ACCOUNT_API_NOT_ACCESS_JWT',anchor_canonical_sha256:anchorHash,chain_head:anchor.chain_head,received_at_utc:'2026-11-04T15:09:28.283Z',queue_name:'sovrint-onyx-admissions-private-v1'};
 const receiptHash=hash(canon(receipt));
 const rec={schema:'sovrint-onyx-remote-admission-v1',request:req,server_attestation:{receipt,canonical_receipt_sha256:receiptHash,signature_algorithm:'Ed25519',signature_base64:sign(null,canon(receipt),witness.privateKey).toString('base64'),witness_key_pem_sha256:pin2}};
 const trust={expectedAnchorSha256:anchorHash,expectedReceiptSha256:receiptHash,expectedRecordSha256:hash(canon(rec)),originPublicKeySha256:pin1,witnessPublicKeySha256:pin2,witnessPublicKeyPem:pub2};
 return {rec,trust};
}
const clone=x=>structuredClone(x);
test('legacy unverified text does not fabricate verification',()=>{
 const r=AuditNode('Institutional breach detected');assert.equal(r.verified,false);assert.equal(r.distortionNeutralized,false);assert.equal('original' in r,false);
});
test('unsigned arbitrary object is unverified',()=>assert.equal(AuditNode({hello:'world'}).verified,false));
test('valid self-contained synthetic Ed25519 receipt and independent trust pass',()=>{
 const {rec,trust}=fixture();const r=AuditNode(rec,trust);assert.equal(r.verified,true);assert.equal(r.distortionNeutralized,false);
});
test('valid synthetic signed receipt fails without separately supplied trust',()=>{const{rec}=fixture();assert.equal(AuditNode(rec).verified,false)});
test('modified anchor content rejected',()=>{const{rec,trust}=fixture();rec.request.anchor.chain_head='b'.repeat(64);assert.equal(verifyOnyxReceipt(rec,trust).verified,false)});
test('altered origin signature rejected',()=>{const{rec,trust}=fixture();rec.request.anchor_signature_base64='A'.repeat(86)+'==';assert.equal(verifyOnyxReceipt(rec,trust).verified,false)});
test('altered witness signature rejected',()=>{const{rec,trust}=fixture();rec.server_attestation.signature_base64='A'.repeat(86)+'==';assert.equal(verifyOnyxReceipt(rec,trust).verified,false)});
test('wrong witness trusted key rejected',()=>{const{rec,trust}=fixture();trust.witnessPublicKeyPem=generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'pem'});assert.equal(verifyOnyxReceipt(rec,trust).verified,false)});
test('wrong external record hash rejected',()=>{const{rec,trust}=fixture();trust.expectedRecordSha256='f'.repeat(64);assert.equal(verifyOnyxReceipt(rec,trust).verified,false)});
test('wrong external receipt hash rejected',()=>{const{rec,trust}=fixture();trust.expectedReceiptSha256='b'.repeat(64);assert.equal(verifyOnyxReceipt(rec,trust).verified,false)});
test('wrong external origin pin rejected',()=>{const{rec,trust}=fixture();trust.originPublicKeySha256='b'.repeat(64);assert.equal(verifyOnyxReceipt(rec,trust).verified,false)});
test('unsafe real-evidence classification rejected',()=>{const{rec,trust}=fixture();rec.request.classification='REAL_EVIDENCE';assert.equal(verifyOnyxReceipt(rec,trust).verified,false)});
test('secret-content flag rejected',()=>{const{rec,trust}=fixture();rec.request.contains_private_key=true;assert.equal(verifyOnyxReceipt(rec,trust).verified,false)});
test('original evidence flag rejected',()=>{const{rec,trust}=fixture();rec.request.contains_original_evidence=true;assert.equal(verifyOnyxReceipt(rec,trust).verified,false)});
test('incorrect queue name rejected',()=>{const{rec,trust}=fixture();rec.server_attestation.receipt.queue_name='public';assert.equal(verifyOnyxReceipt(rec,trust).verified,false)});
test('custody false claim rejected',()=>{const{rec,trust}=fixture();rec.server_attestation.receipt.custody='INDEPENDENT_CUSTODY';assert.equal(verifyOnyxReceipt(rec,trust).verified,false)});
test('unexpected extra field rejected',()=>{const{rec,trust}=fixture();rec.extra='hidden';assert.equal(verifyOnyxReceipt(rec,trust).verified,false)});
test('malformed base64 rejected',()=>{const{rec,trust}=fixture();rec.request.anchor_signature_base64='not-base64';assert.equal(verifyOnyxReceipt(rec,trust).verified,false)});
test('null input rejected',()=>assert.equal(AuditNode(null).verified,false));
test('untrusted caller cannot set verified via object prototype',()=>{const{rec,trust}=fixture();const bogus=Object.create({verified:true});Object.assign(bogus,rec);assert.equal(verifyOnyxReceipt(bogus,trust).verified,false)});
test('no distortion claim even when cryptographic record is valid',()=>{const{rec,trust}=fixture();assert.equal(AuditNode(rec,trust).distortionNeutralized,false)});