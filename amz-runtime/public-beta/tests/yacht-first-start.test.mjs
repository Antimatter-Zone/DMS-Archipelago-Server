import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {PROFILE_SHA,DOMAIN,LAUNCH_DOMAIN,ACTIVATION_DOMAIN,ACTIVATION_ENVELOPE,READY_DOMAIN,
 canonical,sha,publicTrust,verifyHeldReady,verifyActivation,parseCanonical,frameDecoder,encodeFrame}
 from '../../public-beta-yacht-first-start/runtime/launcher.mjs';

const raw=v=>Buffer.from(canonical(v));
function fixture(){
 const pairs=Object.fromEntries(['issuer','provider','launchCommand'].map(k=>[k,generateKeyPairSync('ed25519')]));
 const entry=(name,keyId)=>({keyId,rootPublicKeyPem:pairs[name].publicKey.export({type:'spki',format:'pem'}),
  rootSpkiSha256:sha(pairs[name].publicKey.export({type:'spki',format:'der'}))});
 const definition={schema:'amz.ap.public-beta.yacht-first-start-trust.v1',issuer:entry('issuer',DOMAIN),
  provider:entry('provider',LAUNCH_DOMAIN),launchCommand:entry('launchCommand',ACTIVATION_DOMAIN)};
 const trust=publicTrust(raw(definition)),now=Date.now(),issuedAt=new Date(now).toISOString(),expiresAt=new Date(now+4000).toISOString();
 const challenge={nonce:'a'.repeat(64),process:{pid1StartTicks:'123',workerStartTicks:'125',workerPid:22},expiresAt:new Date(now+30000).toISOString()};
 const roomId=randomUUID(),identity={appVariant:'public-beta',policyId:'public-disposable-beta-v1',environmentId:randomUUID(),dataEpoch:randomUUID(),
  roomId,externalId:`ap-beta-${roomId}-r1`,allocationRevision:1,serverId:'fixture',attemptId:randomUUID(),seedRevision:1,credentialEpoch:1,runtimeLaunchId:randomUUID()};
 const operationId=randomUUID(),serverUuid=randomUUID(),provider={serverUuid,containerId:'b'.repeat(64),imageId:'sha256:'+'c'.repeat(64),volumeId:serverUuid};
 const native={artifactSha256:'d'.repeat(64),profileSha256:'e'.repeat(64),sourceCommit:'f'.repeat(40)},artifactSha256='1'.repeat(64);
 const verified={body:{identity,operationId,provider,native,files:[{name:'public-runtime.json',sha256:'2'.repeat(64)},
  {name:'public-seed.archipelago',sha256:'3'.repeat(64)},{name:'public-publication-scope.json',sha256:'4'.repeat(64)}]}};
 const binding={identity,operationId,nativeInstance:challenge.process,configurationSha256:'2'.repeat(64),seedArtifactSha256:'3'.repeat(64),
  seedNameSha256:'5'.repeat(64),rosterSha256:'6'.repeat(64),browserBuildSha256:'7'.repeat(64),listener:{host:'0.0.0.0',port:38281},native,provider,
  firstStart:{artifactSha256,profileSha256:PROFILE_SHA},publicationScopeSha256:'4'.repeat(64),startupExpiresAt:challenge.expiresAt};
 const held={schema:READY_DOMAIN,binding,listenerReady:true,admissionHeld:true,connectedClients:0,issuedAt,expiresAt};
 const ready=verifyHeldReady(held,{challenge,verified,artifactSha256},now);
 const body={schema:ACTIVATION_DOMAIN,requestId:randomUUID(),nonce:challenge.nonce,heldReadySha256:ready.sha256,binding,
  committedPublicationSha256:'8'.repeat(64),controlDefinitionSha256:'9'.repeat(64),releaseDefinitionSha256:'0'.repeat(64),issuedAt,expiresAt};
 const envelope=(value=body,key=pairs.launchCommand.privateKey,domain=ACTIVATION_DOMAIN)=>({schema:ACTIVATION_ENVELOPE,body:value,
  signature:sign(null,Buffer.from(domain+'\n'+canonical(value)),key).toString('base64')});
 return {pairs,definition,trust,challenge,verified,artifactSha256,held,ready,body,envelope,now};
}

test('actual independent Ed activation joins an observed held launch; verification is data only',()=>{
 const f=fixture();assert.deepEqual(verifyActivation(f.envelope(),f,f.now).body,f.body);
 const profile=readFileSync(new URL('../../public-beta-yacht-first-start/runtime/runtime-profile.json',import.meta.url));
 assert.equal(sha(profile),PROFILE_SHA);const p=JSON.parse(profile);
 assert.equal(p.firstStart.activationTrustDefault,null);assert.equal(p.firstStart.consumerImplemented,false);
 assert.equal(p.firstStart.imageDigest,null);assert.equal(p.bootstrap.startupMilliseconds,30000);
 assert.equal(p.bootstrap.workspaceBytes,81920);
});

test('null trust, another key, provider/issuer purpose, and wrong signature cannot activate',()=>{
 const f=fixture(),none=publicTrust(raw({...f.definition,launchCommand:null}));
 assert.throws(()=>verifyActivation(f.envelope(),{...f,trust:none},f.now));
 for(const env of [f.envelope(f.body,f.pairs.provider.privateKey),f.envelope(f.body,f.pairs.issuer.privateKey),
  f.envelope(f.body,f.pairs.launchCommand.privateKey,DOMAIN),{...f.envelope(),signature:Buffer.alloc(64).toString('base64')}])
  assert.throws(()=>verifyActivation(env,f,f.now));
 const other=fixture();assert.throws(()=>verifyActivation(f.envelope(),{...f,trust:other.trust},f.now));
});

test('a valid CP signature cannot cross the exact observed launch and native tuple',()=>{
 const f=fixture();
 const edits=[v=>v.nonce='b'.repeat(64),v=>v.heldReadySha256='b'.repeat(64),v=>v.binding.identity.dataEpoch=randomUUID(),
  v=>v.binding.identity.runtimeLaunchId=randomUUID(),v=>v.binding.nativeInstance.workerStartTicks='126',
  v=>v.binding.seedArtifactSha256='b'.repeat(64),v=>v.binding.seedNameSha256='b'.repeat(64),
  v=>v.binding.configurationSha256='b'.repeat(64),v=>v.binding.rosterSha256='b'.repeat(64),
  v=>v.binding.listener.port++,v=>v.binding.provider.containerId='b'.repeat(63)+'c',
  v=>v.binding.firstStart.artifactSha256='b'.repeat(64),v=>v.binding.publicationScopeSha256='b'.repeat(64),
  v=>v.committedPublicationSha256=null,v=>v.controlDefinitionSha256+='\n',v=>v.extra=true];
 for(const edit of edits){const body=structuredClone(f.body);edit(body);assert.throws(()=>verifyActivation(f.envelope(body),f,f.now));}
});

test('held-ready refuses a ready/open client or mismatched sealed source/configuration',()=>{
 const f=fixture();
 for(const edit of [v=>v.admissionHeld=false,v=>v.connectedClients=1,v=>v.listenerReady=false,
  v=>v.binding.configurationSha256='f'.repeat(64),v=>v.binding.seedArtifactSha256='f'.repeat(64),
  v=>v.binding.identity.roomId=randomUUID(),v=>v.binding.native.sourceCommit='0'.repeat(40),
  v=>v.binding.provider.imageId='sha256:'+'0'.repeat(64),v=>v.binding.firstStart.profileSha256='0'.repeat(64),
  v=>v.binding.startupExpiresAt=new Date(f.now+31000).toISOString(),v=>v.binding.listener.host='127.0.0.1']){
  const held=structuredClone(f.held);edit(held);assert.throws(()=>verifyHeldReady(held,f,f.now));
 }
});

test('activation never renews the original startup or short held-ready window',()=>{
 const f=fixture();assert.throws(()=>verifyActivation(f.envelope(),f,f.now+4000));
 for(const change of [{issuedAt:new Date(f.now+1).toISOString()}, {expiresAt:new Date(f.now+5001).toISOString()},
  {expiresAt:new Date(f.now+4001).toISOString()}, {expiresAt:new Date(f.now-1).toISOString()}])
  assert.throws(()=>verifyActivation(f.envelope({...f.body,...change}),f,f.now));
 const shorter={...f.challenge,expiresAt:new Date(f.now+2000).toISOString()};
 assert.throws(()=>verifyActivation(f.envelope(),{...f,challenge:shorter},f.now));
});

test('activation root cannot be private, self-declared, or interchangeable with existing purposes',()=>{
 const f=fixture();
 for(const edit of [v=>v.launchCommand={...v.provider,keyId:ACTIVATION_DOMAIN},v=>v.launchCommand.keyId=LAUNCH_DOMAIN,
  v=>v.launchCommand.rootPublicKeyPem=f.pairs.launchCommand.privateKey.export({type:'pkcs8',format:'pem'}),
  v=>v.launchCommand.rootSpkiSha256='0'.repeat(64),v=>v.launchCommand.rootSpkiSha256+='\n',v=>v.activationAllowed=true]){
  const v=structuredClone(f.definition);edit(v);assert.throws(()=>publicTrust(raw(v)));
 }
});

test('six inherited frames remain bounded and canonical; excess and incomplete replies refuse',()=>{
 const frame=encodeFrame({kind:'data-only'}),received=[],decode=frameDecoder(v=>received.push(v));
 for(let count=0;count<6;count++)for(const byte of frame)decode(Buffer.from([byte]));
 decode.finish();assert.equal(received.length,6);assert.throws(()=>decode(frame));
 const partial=frameDecoder(()=>{});partial(frame.subarray(0,-1));assert.throws(()=>partial.finish());
 for(const text of ['{}\n','{"a":1,"a":1}','\ufeff{}','[]','{"x":1e400}'])assert.throws(()=>parseCanonical(Buffer.from(text)));
});

test('accepted production bootstrap and native loader provenance remains exact',()=>{
 const paths={'../../public-beta-yacht-production-bootstrap/runtime/bootstrap.py':'194beaeb0d0264d5d5780ef85424a68eef2d9c19c55b543d073321dd2fa388d4',
  '../../public-beta-yacht-production-bootstrap/runtime/launcher.mjs':'8eab0f2f1e24810954eddd46f1b70569d51bc6e22ae5390362693d1cc62dd14c',
  '../../public-beta-yacht-production-bootstrap/issuer/publisher.py':'72ce2c025e35ebde70f5d70c82ba5015e428b64bea7f227e0da62813bb8ccf63',
  '../../public-beta-yacht-publication/runtime/loader.py':'9fdcfab688d6563c766cd6bb178cba6903dd9e4eb1f4ff1a23d3320e74804c22'};
 for(const [file,digest] of Object.entries(paths))assert.equal(sha(readFileSync(new URL(file,import.meta.url))),digest);
});
