import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {spawn} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {PROFILE_SHA,CHANNEL,DOMAIN,sha,canonical,parseCanonical,publicTrust,verifySeal,encodeFrame,frameDecoder} from '../../public-beta-yacht-bootstrap/runtime/launcher.mjs';

const here=path.dirname(fileURLToPath(import.meta.url));
const profile=JSON.parse(readFileSync(path.join(here,'../../public-beta-yacht-bootstrap/runtime/runtime-profile.json')));
function fixture(){
 const keys=generateKeyPairSync('ed25519'),pem=keys.publicKey.export({type:'spki',format:'pem'}),spki=sha(keys.publicKey.export({type:'spki',format:'der'}));
 const trust=publicTrust(Buffer.from(canonical({schema:'amz.ap.public-beta.bootstrap-trust.v1',mode:'synthetic-qa-only',rootPublicKeyPem:pem,rootSpkiSha256:spki})));
 const now=Date.now(),nonce='a'.repeat(64),artifactSha256='b'.repeat(64);
 const challenge={schema:'amz.ap.public-beta.bootstrap-challenge.v1',nonce,process:{pid1StartTicks:'10',workerStartTicks:'11',workerPid:2},bootstrapArtifactSha256:artifactSha256,profileSha256:PROFILE_SHA,nativeRoot:{device:'1:1',inode:'1'},issuedAt:new Date(now).toISOString(),expiresAt:new Date(now+30000).toISOString()};
 const roomId=randomUUID(),identity={appVariant:'public-beta',policyId:'public-disposable-beta-v1',environmentId:randomUUID(),dataEpoch:randomUUID(),roomId,externalId:`ap-beta-${roomId}-r1`,allocationRevision:1,serverId:'synthetic-source-fixture',attemptId:randomUUID(),seedRevision:1,credentialEpoch:1,runtimeLaunchId:randomUUID()};
 const body={schema:DOMAIN,sealId:randomUUID(),operationId:randomUUID(),nonce,challengeSha256:sha(Buffer.from(canonical(challenge))),process:challenge.process,identity,native:{artifactSha256:profile.native.artifactSha256,profileSha256:profile.native.profileSha256,sourceCommit:profile.native.sourceCommit},bootstrapArtifactSha256:artifactSha256,provider:{serverUuid:randomUUID(),containerId:'c'.repeat(64),imageId:'sha256:'+'d'.repeat(64),volumeId:null,attestation:'synthetic-qa-only'},files:profile.files.map(f=>({name:f.name,bytes:1,sha256:'e'.repeat(64),device:'1:1',inode:'1',uid:65532,gid:65532,mode:0o600})),issuedAt:new Date(now).toISOString(),expiresAt:new Date(now+4500).toISOString()};body.provider.volumeId=body.provider.serverUuid;
 const seal=value=>Buffer.from(canonical({schema:'amz.ap.public-beta.bootstrap-envelope.v1',body:value,signature:sign(null,Buffer.from(DOMAIN+'\n'+canonical(value)),keys.privateKey).toString('base64')}));
 return {keys,trust,challenge,artifactSha256,body,seal,now};
}
test('profile pin and explicit synthetic-only public trust have no production fallback',()=>{
 const raw=readFileSync(path.join(here,'../../public-beta-yacht-bootstrap/runtime/runtime-profile.json'));assert.equal(sha(raw),PROFILE_SHA);
 assert.equal(profile.trust.defaultMode,'unconfigured');const f=fixture();assert.equal(f.trust.mode,'synthetic-qa-only');
 for(const mode of ['unconfigured','production','protected'])assert.throws(()=>publicTrust(Buffer.from(canonical({schema:'amz.ap.public-beta.bootstrap-trust.v1',mode,rootPublicKeyPem:f.trust.rootPublicKeyPem,rootSpkiSha256:f.trust.rootSpkiSha256}))));
 assert.throws(()=>publicTrust(Buffer.from(canonical({schema:'amz.ap.public-beta.bootstrap-trust.v1',mode:'synthetic-qa-only',rootPublicKeyPem:f.keys.privateKey.export({type:'pkcs8',format:'pem'}),rootSpkiSha256:f.trust.rootSpkiSha256}))));
});
test('actual Node Ed25519 verifies the exact domain and bound canonical body',()=>{
 const f=fixture(),raw=f.seal(f.body),result=verifySeal(raw,{profile,...f},f.now);assert.equal(result.sealSha256,sha(raw));assert.deepEqual(result.body,f.body);
 const changed=JSON.parse(raw);changed.signature=Buffer.from(changed.signature,'base64').fill(0).toString('base64');assert.throws(()=>verifySeal(Buffer.from(canonical(changed)),{profile,...f},f.now));
 const other=fixture();assert.throws(()=>verifySeal(raw,{profile,...f,trust:other.trust},f.now));
});
test('correct signatures cannot change nonce, component, process, file roles or issuer class',()=>{
 const f=fixture();for(const edit of [b=>b.nonce='f'.repeat(64),b=>b.process={...b.process,workerStartTicks:'12'},b=>b.native.profileSha256='0'.repeat(64),b=>b.provider.attestation='production',b=>b.files[0].name='../keys',b=>b.files[0].uid=0,b=>b.files[0].bytes=999999,b=>b.extra=true]){const b=structuredClone(f.body);edit(b);assert.throws(()=>verifySeal(f.seal(b),{profile,...f},f.now));}
});
test('seal time is original, bounded and cannot extend the fresh challenge',()=>{
 const f=fixture();assert.throws(()=>verifySeal(f.seal(f.body),{profile,...f},f.now+4500));
 for(const edit of [b=>b.expiresAt=new Date(f.now+5001).toISOString(),b=>b.issuedAt=new Date(f.now+1).toISOString(),b=>b.expiresAt=new Date(f.now-1).toISOString()]){const b=structuredClone(f.body);edit(b);assert.throws(()=>verifySeal(f.seal(b),{profile,...f},f.now));}
});
test('fatal UTF8, BOM, duplicates and noncanonical or concatenated frames refuse',()=>{
 for(const raw of [Buffer.from('\ufeff{}'),Buffer.from('{}\n'),Buffer.from('{"a":1,"a":1}'),Buffer.from('{}{}'),Buffer.from([0xff])])assert.throws(()=>parseCanonical(raw));
 const f=fixture(),raw=f.seal(f.body);assert.throws(()=>verifySeal(Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),raw]),{profile,...f},f.now));
});
test('private frame decoder has bounded partial reads, exact EOF and finite frame count',()=>{
 const values=[],frame=encodeFrame({schema:CHANNEL,a:1}),decode=frameDecoder(v=>values.push(v));decode(frame.subarray(0,3));assert.equal(values.length,0);decode(frame.subarray(3));decode.finish();assert.equal(values.length,1);
 const incomplete=frameDecoder(()=>{});incomplete(frame.subarray(0,5));assert.throws(()=>incomplete.finish());
 const large=Buffer.alloc(4);large.writeUInt32BE(32769);assert.throws(()=>frameDecoder(()=>{})(large));
 const many=frameDecoder(()=>{});for(let i=0;i<3;i++)many(frame);assert.throws(()=>many(frame));
});
test('normal entrypoint code retains fixed worker, original parent bound and strict frame kinds',()=>{
 const source=readFileSync(path.join(here,'../../public-beta-yacht-bootstrap/runtime/launcher.mjs'),'utf8');
 assert(source.includes("frame.kind==='challenge'"));assert(source.includes("frame.kind==='verify-seal'"));assert(source.includes("reply(-1,'startup-bound'"));assert(source.includes('startedWall+30000'));
 assert(source.includes("'/usr/local/bin/python',['-I','-B',OWNED+'/bootstrap.py']"));assert(!source.includes('createServer'));assert(!source.includes('process.env'));assert(source.includes('await settle()'));
});
test('real private pipes reach Python actual channel only after actual Node signature verification',{skip:process.platform!=='linux'},async()=>{
 const python=process.env.AMZ_BOOTSTRAP_TEST_PYTHON;assert(python&&path.isAbsolute(python),'Python wrapper must supply its actual executable, never an alias');
 const f=fixture(),worker=path.join(here,'../../public-beta-yacht-bootstrap/runtime/bootstrap.py');
 const program=`import importlib.util,json,sys,time,hashlib\nfrom pathlib import Path\nspec=importlib.util.spec_from_file_location('actual_bootstrap_channel',sys.argv[1]);b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)\ncontext=json.loads(sys.argv[2]);s=b.parent_startup(b.Budget(30000));c=context['challenge'];c['process']['workerPid']=__import__('os').getpid()\np=b.PrivateChannel(c,s,context['signer']);p.register()\nraw=__import__('base64').b64decode(sys.argv[3]);proof=p.verify(raw,b.Budget(5000,parent=s,issued=json.loads(raw)['body']['issuedAt'],expires=json.loads(raw)['body']['expiresAt']));v=b.approval(proof,p);print(json.dumps({'verified':v['nonce']==c['nonce'],'consumed':v['consumed']}));p.close()\n`;
 // The child PID is needed in the challenge, so its fixed script pauses on
 // stdin before verification; the seal is supplied through its ordinary test
 // stdin only. No production main, native files or grant is exercised here.
 const actualProgram=program.replace("raw=__import__('base64').b64decode(sys.argv[3])","raw=__import__('base64').b64decode(sys.stdin.buffer.readline().strip())");
 const child=spawn(python,['-I','-B','-c',actualProgram,worker,JSON.stringify({challenge:f.challenge,signer:f.trust.rootSpkiSha256}),'unused'],{stdio:['pipe','pipe','pipe','pipe','pipe']});
 let output='',errors='',challenge,closed=false,timer,settled=false,resolveStopped,rejectStopped;
 const stopped=new Promise((resolve,reject)=>{resolveStopped=resolve;rejectStopped=reject;});
 const failFixture=error=>{if(!settled){settled=true;rejectStopped(error??Error('Owned source IPC fixture failed'));}child.kill('SIGKILL');for(const stream of child.stdio)stream?.destroy();child.unref();};
 child.once('error',failFixture);child.once('close',value=>{closed=true;if(!settled){settled=true;resolveStopped(value);}});
 for(const stream of child.stdio)stream?.on('error',failFixture);
 timer=setTimeout(()=>failFixture(Error('Owned source IPC fixture exceeded its original deadline')),7000);
 child.stdout.on('data',c=>{output+=c;if(Buffer.byteLength(output)>32768)failFixture();});child.stderr.on('data',c=>{errors+=c;if(Buffer.byteLength(errors)>32768)failFixture();});
 const send=(sequence,kind,body)=>child.stdio[4].write(encodeFrame({schema:CHANNEL,direction:'parent-to-worker',sequence,kind,body}));
 const decode=frameDecoder(frame=>{if(frame.sequence===0){challenge=frame.body;send(0,'challenge-accepted',{nonce:challenge.nonce,challengeSha256:sha(Buffer.from(canonical(challenge)))});const body={...f.body,process:challenge.process,challengeSha256:sha(Buffer.from(canonical(challenge)))};child.stdin.end(f.seal(body).toString('base64')+'\n');}else{const raw=Buffer.from(frame.body.sealBase64,'base64');const verified=verifySeal(raw,{profile,trust:f.trust,challenge,artifactSha256:f.artifactSha256});send(1,'seal-verified',{requestId:frame.body.requestId,nonce:challenge.nonce,sealSha256:verified.sealSha256,bodySha256:verified.bodySha256,signerSpkiSha256:f.trust.rootSpkiSha256});}});
 child.stdio[3].on('data',c=>{try{decode(c);}catch(error){failFixture(error);}});
 try{send(-1,'startup-bound',{issuedAt:new Date(f.now).toISOString(),expiresAt:new Date(f.now+30000).toISOString()});const code=await stopped;assert.equal(code,0,errors);assert.deepEqual(JSON.parse(output),{verified:true,consumed:false});decode.finish();}finally{clearTimeout(timer);if(!closed)failFixture();for(const stream of child.stdio)stream?.destroy();}
});
