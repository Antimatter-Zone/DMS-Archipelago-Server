import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {PROFILE_SHA,DOMAIN,LAUNCH_DOMAIN,canonical,sha,publicTrust,verifySeal,parseCanonical,
  frameDecoder,encodeFrame} from '../../public-beta-yacht-production-bootstrap/runtime/launcher.mjs';

const profileFile=new URL('../../public-beta-yacht-production-bootstrap/runtime/runtime-profile.json',import.meta.url);
const profile=JSON.parse(readFileSync(profileFile));
const raw=value=>Buffer.from(canonical(value));
const envelope=(body,domain,schema,key)=>({schema,body,signature:sign(null,Buffer.from(domain+'\n'+canonical(body)),key).toString('base64')});
function fixture(){
 const issuer=generateKeyPairSync('ed25519'),provider=generateKeyPairSync('ed25519');
 const entry=(pair,keyId)=>({keyId,rootPublicKeyPem:pair.publicKey.export({type:'spki',format:'pem'}),rootSpkiSha256:sha(pair.publicKey.export({type:'spki',format:'der'}))});
 const definition={schema:'amz.ap.public-beta.production-bootstrap-trust.v1',issuer:entry(issuer,DOMAIN),provider:entry(provider,LAUNCH_DOMAIN)};
 const trust=publicTrust(raw(definition)),now=Date.now(),issuedAt=new Date(now).toISOString(),expiresAt=new Date(now+4000).toISOString();
 const challenge={schema:'amz.ap.public-beta.production-bootstrap-challenge.v1',nonce:'a'.repeat(64),process:{pid1StartTicks:'1',workerStartTicks:'2',workerPid:3},
  bootstrapArtifactSha256:'b'.repeat(64),profileSha256:PROFILE_SHA,nativeRoot:{device:'1:2',inode:'3'},bootstrapRoot:{device:'1:2',inode:'4'},issuedAt,expiresAt:new Date(now+30000).toISOString()};
 const roomId=randomUUID(),identity={appVariant:'public-beta',policyId:'public-disposable-beta-v1',environmentId:randomUUID(),dataEpoch:randomUUID(),roomId,externalId:`ap-beta-${roomId}-r1`,allocationRevision:1,serverId:'source-fixture',attemptId:randomUUID(),seedRevision:1,credentialEpoch:1,runtimeLaunchId:randomUUID()};
 const providerIdentity={serverUuid:randomUUID(),containerId:'c'.repeat(64),imageId:'sha256:'+'d'.repeat(64)};providerIdentity.volumeId=providerIdentity.serverUuid;
 const native=Object.fromEntries(['artifactSha256','profileSha256','sourceCommit'].map(k=>[k,profile.native[k]]));
 const files=profile.files.map((f,i)=>({name:f.name,bytes:1,sha256:String(i+1).repeat(64),device:'1:2',inode:String(i+5),uid:65532,gid:65532,mode:0o600}));
 const operationId=randomUUID(),launch={schema:LAUNCH_DOMAIN,operationId,provider:providerIdentity,identitySha256:sha(raw(identity)),challengeSha256:sha(raw(challenge)),process:challenge.process,nativeRoot:challenge.nativeRoot,bootstrapRoot:challenge.bootstrapRoot,
  bootstrapArtifactSha256:challenge.bootstrapArtifactSha256,native,filesSha256:sha(raw(files)),publicationScopeSha256:files.find(f=>f.name==='public-publication-scope.json').sha256,
  providerProfileSha256:'e'.repeat(64),placementDefinitionSha256:'f'.repeat(64),physicalPermitSha256:'1'.repeat(64),nodeIdentitySha256:'2'.repeat(64),issuedAt,expiresAt};
 const body={schema:DOMAIN,sealId:randomUUID(),operationId,nonce:challenge.nonce,challengeSha256:sha(raw(challenge)),process:challenge.process,identity,native,
  bootstrapArtifactSha256:challenge.bootstrapArtifactSha256,provider:{...providerIdentity,attestation:'current-provider-launch-v1'},files,launch:null,issuedAt,expiresAt};
 const providerEnvelope=value=>envelope(value,LAUNCH_DOMAIN,'amz.ap.public-beta.yacht-provider-launch-envelope.v1',provider.privateKey);
 const seal=value=>raw(envelope(value,DOMAIN,'amz.ap.public-beta.production-bootstrap-envelope.v1',issuer.privateKey));
 body.launch=providerEnvelope(launch);
 return {issuer,provider,definition,trust,challenge,artifactSha256:challenge.bootstrapArtifactSha256,body,launch,providerEnvelope,seal,now};
}

test('separate source profile and actual independent Node Ed25519 signatures join the complete launch',()=>{
 const f=fixture();assert.equal(sha(readFileSync(profileFile)),PROFILE_SHA);
 assert.equal(profile.trust.defaultMode,'unconfigured');assert.equal(profile.native.ownedFiles,22);
 assert.deepEqual(verifySeal(f.seal(f.body),{profile,...f},f.now).body,f.body);
 assert.equal(profile.qualification.issuerEnrolled,false);assert.equal(profile.qualification.providerEnrolled,false);
});

test('an issuer signature cannot replace actual independent provider signature or purpose',()=>{
 const f=fixture();
 for(const forged of [envelope(f.launch,LAUNCH_DOMAIN,'amz.ap.public-beta.yacht-provider-launch-envelope.v1',f.issuer.privateKey),
  envelope(f.launch,DOMAIN,'amz.ap.public-beta.yacht-provider-launch-envelope.v1',f.provider.privateKey),
  {...f.body.launch,signature:Buffer.alloc(64).toString('base64')}]){
  assert.throws(()=>verifySeal(f.seal({...f.body,launch:forged}),{profile,...f},f.now));
 }
 const other=fixture();assert.throws(()=>verifySeal(f.seal(f.body),{profile,...f,trust:other.trust},f.now));
});

test('valid independent signatures cannot cross operation/provider/process/root/files/source/permit purposes',()=>{
 const f=fixture();
 const edits=[v=>v.operationId=randomUUID(),v=>v.provider.containerId='9'.repeat(64),v=>v.provider.volumeId=randomUUID(),
  v=>v.identitySha256='9'.repeat(64),v=>v.challengeSha256='9'.repeat(64),v=>v.process.workerStartTicks='22',
  v=>v.nativeRoot.inode='44',v=>v.bootstrapRoot.inode='33',v=>v.bootstrapArtifactSha256='9'.repeat(64),v=>v.native.sourceCommit='9'.repeat(40),
  v=>v.filesSha256='9'.repeat(64),v=>v.publicationScopeSha256='9'.repeat(64),v=>v.physicalPermitSha256=null,
  v=>v.providerProfileSha256+='\n',v=>v.extra=true];
 for(const edit of edits){const launch=structuredClone(f.launch);edit(launch);const body={...f.body,launch:f.providerEnvelope(launch)};
  assert.throws(()=>verifySeal(f.seal(body),{profile,...f},f.now));}
 for(const edit of [b=>b.provider.attestation='synthetic-qa-only',b=>b.files[0].mode=0o644,b=>b.files[0].name='../other',b=>b.native.profileSha256='9'.repeat(64)]){
  const body=structuredClone(f.body);edit(body);assert.throws(()=>verifySeal(f.seal(body),{profile,...f},f.now));
 }
});

test('public root definitions cannot collapse purposes, accept private keys or use synthetic mode',()=>{
 const f=fixture();
 for(const edit of [d=>d.provider={...d.issuer,keyId:LAUNCH_DOMAIN},d=>d.provider.keyId=DOMAIN,
  d=>d.issuer.rootPublicKeyPem=f.issuer.privateKey.export({type:'pkcs8',format:'pem'}),d=>d.issuer.rootSpkiSha256='1'.repeat(64),
  d=>d.mode='production',d=>d.issuer.rootSpkiSha256+='\n']){
  const definition=structuredClone(f.definition);edit(definition);assert.throws(()=>publicTrust(raw(definition)));
 }
 assert.throws(()=>publicTrust(raw({schema:f.definition.schema,issuer:null,provider:null})));
 assert.throws(()=>publicTrust(raw({schema:'amz.ap.public-beta.bootstrap-trust.v1',mode:'synthetic-qa-only',...f.definition.issuer})));
});

test('provider and issuer retain their original short window inside the original challenge',()=>{
 const f=fixture();assert.throws(()=>verifySeal(f.seal(f.body),{profile,...f},f.now+4000));
 for(const edit of [v=>v.expiresAt=new Date(f.now+5001).toISOString(),v=>v.issuedAt=new Date(f.now+1).toISOString(),v=>v.expiresAt=new Date(f.now-1).toISOString()]){
  const launch=structuredClone(f.launch);edit(launch);assert.throws(()=>verifySeal(f.seal({...f.body,launch:f.providerEnvelope(launch)}),{profile,...f},f.now));
 }
 const short={...f.launch,expiresAt:new Date(f.now+1000).toISOString()};
 assert.throws(()=>verifySeal(f.seal({...f.body,launch:f.providerEnvelope(short)}),{profile,...f},f.now));
});

test('canonical frames refuse malformed encodings and incomplete or excess private messages',()=>{
 for(const value of ['{}\n','{"a":1,"a":1}','\ufeff{}','{}{}','[]'])assert.throws(()=>parseCanonical(Buffer.from(value)));
 const messages=[],frame=encodeFrame({schema:'source-fixture'}),decoder=frameDecoder(v=>messages.push(v));
 for(let i=0;i<frame.length;i++)decoder(frame.subarray(i,i+1));decoder.finish();assert.equal(messages.length,1);
 const partial=frameDecoder(()=>{});partial(frame.subarray(0,-1));assert.throws(()=>partial.finish());
 const extra=frameDecoder(()=>{});for(let i=0;i<3;i++)extra(frame);assert.throws(()=>extra(frame));
});

test('accepted historical bootstrap source bytes remain exact',()=>{
 const old=readFileSync(new URL('../../public-beta-yacht-bootstrap/runtime/launcher.mjs',import.meta.url));
 assert.equal(sha(old),'8173d91e359f87349b711456ee8a69968df35f7d75ff354737e80bbfe524f2d2');
 assert.equal(sha(readFileSync(new URL('../../public-beta-yacht-bootstrap/runtime/bootstrap.py',import.meta.url))),'4f9ca5e0b4c00a26cc730cda19ef37966bdeb6554dd8d7bc1b9700e12b755c43');
});
