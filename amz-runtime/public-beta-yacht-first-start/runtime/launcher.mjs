// New normal PID1 entrypoint. No listener or automatic startup on import.
import {constants} from 'node:fs';
import {lstat,open,realpath} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {spawn} from 'node:child_process';

const OWNED='/opt/amz-ap-first-start',PARENT='/opt/amz-ap-public';
export const PROFILE_SHA='ce3658a8c96fb7b5e29506d8faf728edd8e962982e5cbad535e18add7365e02d';
export const CHANNEL='amz.ap.public-beta.yacht-first-start-channel.v1';
export const DOMAIN='amz.ap.public-beta.production-bootstrap-seal.v1';
export const LAUNCH_DOMAIN='amz.ap.public-beta.yacht-provider-launch.v1';
export const ACTIVATION_DOMAIN='amz.ap.public-beta.yacht-first-start-activation.v1';
export const ACTIVATION_ENVELOPE='amz.ap.public-beta.yacht-first-start-activation-envelope.v1';
export const READY_DOMAIN='amz.ap.public-beta.yacht-first-start-held-ready.v1';
const SHA=/^[a-f0-9]{64}$/,UUID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const IDENTITY=['appVariant','policyId','environmentId','dataEpoch','roomId','externalId','allocationRevision','serverId','attemptId','seedRevision','credentialEpoch','runtimeLaunchId'];
const need=value=>{if(!value)throw Error('bootstrap_runtime_refused');};
export const sha=raw=>createHash('sha256').update(raw).digest('hex');
export const canonical=value=>value===null||typeof value!=='object'?JSON.stringify(value):Array.isArray(value)?'['+value.map(canonical).join(',')+']':'{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
const exact=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const instant=value=>typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value;
const decimal=value=>typeof value==='string'&&/^[0-9]{1,20}$/.test(value);
export function parseCanonical(raw,maximum=32768){
 need(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=maximum);
 const text=new TextDecoder('utf-8',{fatal:true}).decode(raw),value=JSON.parse(text);
 need(Buffer.from(text).equals(raw)&&exact(value,Object.keys(value))&&canonical(value)===text);return value;
}
export function publicTrust(raw){
 const value=parseCanonical(raw,4096);need(exact(value,['schema','issuer','provider','launchCommand'])&&value.schema==='amz.ap.public-beta.yacht-first-start-trust.v1');
 const capture=(v,purpose)=>{need(exact(v,['keyId','rootPublicKeyPem','rootSpkiSha256'])&&v.keyId===purpose&&typeof v.rootPublicKeyPem==='string'&&v.rootPublicKeyPem.length<=512&&/^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n?$/.test(v.rootPublicKeyPem)&&typeof v.rootSpkiSha256==='string'&&v.rootSpkiSha256.length===64&&SHA.test(v.rootSpkiSha256));
  const key=createPublicKey(v.rootPublicKeyPem);need(key.asymmetricKeyType==='ed25519'&&sha(key.export({type:'spki',format:'der'}))===v.rootSpkiSha256);return Object.freeze({...v,key});};
 const issuer=capture(value.issuer,DOMAIN),provider=capture(value.provider,LAUNCH_DOMAIN);
 need(issuer.rootSpkiSha256!==provider.rootSpkiSha256);
 const launchCommand=value.launchCommand===null?null:capture(value.launchCommand,ACTIVATION_DOMAIN);
 need(!launchCommand||![issuer.rootSpkiSha256,provider.rootSpkiSha256].includes(launchCommand.rootSpkiSha256));
 return Object.freeze({schema:value.schema,issuer,provider,launchCommand});
}
function signed(raw,schema,domain,key,maximum){
 const envelope=parseCanonical(raw,maximum);need(exact(envelope,['schema','body','signature'])&&envelope.schema===schema&&typeof envelope.signature==='string');
 const signature=Buffer.from(envelope.signature,'base64');need(signature.length===64&&signature.toString('base64')===envelope.signature&&verify(null,Buffer.from(domain+'\n'+canonical(envelope.body)),key,signature));return envelope.body;
}
const rootIdentity=v=>exact(v,['device','inode'])&&typeof v.device==='string'&&v.device.length<=21&&/^[0-9]{1,10}:[0-9]{1,10}$/.test(v.device)&&typeof v.inode==='string'&&v.inode.length<=20&&/^[1-9][0-9]{0,19}$/.test(v.inode);
function originalWindow(body,challenge,now){need(instant(body.issuedAt)&&instant(body.expiresAt)&&Date.parse(body.issuedAt)<=now&&now<Date.parse(body.expiresAt)&&Date.parse(body.expiresAt)-Date.parse(body.issuedAt)>0&&Date.parse(body.expiresAt)-Date.parse(body.issuedAt)<=5000&&Date.parse(body.expiresAt)<=Date.parse(challenge.expiresAt));}
export function verifyLaunch(envelope,{trust,challenge,artifactSha256,body},now){
 const raw=Buffer.from(canonical(envelope)),launch=signed(raw,'amz.ap.public-beta.yacht-provider-launch-envelope.v1',LAUNCH_DOMAIN,trust.provider.key,8192);
 need(exact(launch,['schema','operationId','provider','identitySha256','challengeSha256','process','nativeRoot','bootstrapRoot','bootstrapArtifactSha256','native','filesSha256','publicationScopeSha256','providerProfileSha256','placementDefinitionSha256','physicalPermitSha256','nodeIdentitySha256','issuedAt','expiresAt'])&&launch.schema===LAUNCH_DOMAIN);
 need(launch.operationId===body.operationId&&exact(launch.provider,['serverUuid','containerId','imageId','volumeId'])&&['serverUuid','containerId','imageId','volumeId'].every(k=>launch.provider[k]===body.provider[k]));
 need(launch.identitySha256===sha(Buffer.from(canonical(body.identity)))&&launch.challengeSha256===body.challengeSha256&&canonical(launch.process)===canonical(challenge.process)&&rootIdentity(launch.nativeRoot)&&rootIdentity(launch.bootstrapRoot)&&canonical(launch.nativeRoot)===canonical(challenge.nativeRoot)&&canonical(launch.bootstrapRoot)===canonical(challenge.bootstrapRoot));
 need(launch.bootstrapArtifactSha256===artifactSha256&&canonical(launch.native)===canonical(body.native)&&launch.filesSha256===sha(Buffer.from(canonical(body.files)))&&launch.publicationScopeSha256===body.files.find(f=>f.name==='public-publication-scope.json').sha256);
 for(const k of ['providerProfileSha256','placementDefinitionSha256','physicalPermitSha256','nodeIdentitySha256'])need(typeof launch[k]==='string'&&launch[k].length===64&&SHA.test(launch[k]));
 originalWindow(launch,challenge,now);need(Date.parse(body.issuedAt)>=Date.parse(launch.issuedAt)&&Date.parse(body.expiresAt)<=Date.parse(launch.expiresAt));return launch;
}
export function verifySeal(raw,{profile,trust,challenge,artifactSha256},now=Date.now()){
 const body=signed(raw,'amz.ap.public-beta.production-bootstrap-envelope.v1',DOMAIN,trust.issuer.key,16384);
 need(exact(body,['schema','sealId','operationId','nonce','challengeSha256','process','identity','native','bootstrapArtifactSha256','provider','files','launch','issuedAt','expiresAt'])&&body.schema===DOMAIN);
 need(typeof body.sealId==='string'&&UUID.test(body.sealId)&&typeof body.operationId==='string'&&UUID.test(body.operationId)&&body.nonce===challenge.nonce&&body.challengeSha256===sha(Buffer.from(canonical(challenge)))&&canonical(body.process)===canonical(challenge.process)&&body.bootstrapArtifactSha256===artifactSha256);
 need(exact(body.native,['artifactSha256','profileSha256','sourceCommit'])&&body.native.artifactSha256===profile.native.artifactSha256&&body.native.profileSha256===profile.native.profileSha256&&body.native.sourceCommit===profile.native.sourceCommit);
 const b=body.identity;need(exact(b,IDENTITY)&&b.appVariant==='public-beta'&&b.policyId==='public-disposable-beta-v1'&&['environmentId','dataEpoch','roomId','attemptId','runtimeLaunchId'].every(k=>typeof b[k]==='string'&&UUID.test(b[k]))&&['allocationRevision','seedRevision','credentialEpoch'].every(k=>Number.isSafeInteger(b[k])&&b[k]>0&&b[k]<=1000000000)&&b.externalId===`ap-beta-${b.roomId}-r${b.allocationRevision}`&&typeof b.serverId==='string'&&/^[A-Za-z0-9_-]{1,80}$/.test(b.serverId));
 const p=body.provider;need(exact(p,['serverUuid','containerId','imageId','volumeId','attestation'])&&p.attestation==='current-provider-launch-v1'&&typeof p.serverUuid==='string'&&p.serverUuid.length===36&&UUID.test(p.serverUuid)&&p.volumeId===p.serverUuid&&typeof p.containerId==='string'&&p.containerId.length===64&&SHA.test(p.containerId)&&typeof p.imageId==='string'&&p.imageId.length===71&&/^sha256:[a-f0-9]{64}$/.test(p.imageId));
 need(Array.isArray(body.files)&&body.files.length===5&&body.files.every((f,i)=>exact(f,['name','bytes','sha256','device','inode','uid','gid','mode'])&&f.name===profile.files[i].name&&Number.isSafeInteger(f.bytes)&&f.bytes>0&&f.bytes<=profile.files[i].maximumBytes&&typeof f.sha256==='string'&&SHA.test(f.sha256)&&typeof f.device==='string'&&/^[0-9]{1,10}:[0-9]{1,10}$/.test(f.device)&&decimal(f.inode)&&f.uid===65532&&f.gid===65532&&f.mode===0o600));
 originalWindow(body,challenge,now);verifyLaunch(body.launch,{trust,challenge,artifactSha256,body},now);
 return Object.freeze({body,sealSha256:sha(raw),bodySha256:sha(Buffer.from(canonical(body)))});
}
/** DATA/signature verification only. Production calls this exclusively from
 * the real inherited worker pipe; no returned object opens a native barrier. */
export function verifyHeldReady(value,{challenge,verified,artifactSha256},now=Date.now()){
 need(exact(value,['schema','binding','listenerReady','admissionHeld','connectedClients','issuedAt','expiresAt'])&&value.schema===READY_DOMAIN&&value.listenerReady===true&&value.admissionHeld===true&&value.connectedClients===0);
 const b=value.binding,s=verified.body;
 need(exact(b,['identity','operationId','nativeInstance','configurationSha256','seedArtifactSha256','seedNameSha256','rosterSha256','browserBuildSha256','listener','native','provider','firstStart','publicationScopeSha256','startupExpiresAt']));
 need(canonical(b.identity)===canonical(s.identity)&&b.operationId===s.operationId&&canonical(b.nativeInstance)===canonical(challenge.process)&&canonical(b.native)===canonical(s.native));
 need(exact(b.provider,['serverUuid','containerId','imageId','volumeId'])&&Object.keys(b.provider).every(k=>b.provider[k]===s.provider[k]));
 need(exact(b.firstStart,['artifactSha256','profileSha256'])&&b.firstStart.artifactSha256===artifactSha256&&b.firstStart.profileSha256===PROFILE_SHA);
 for(const k of ['configurationSha256','seedArtifactSha256','seedNameSha256','rosterSha256','browserBuildSha256','publicationScopeSha256'])need(typeof b[k]==='string'&&b[k].length===64&&SHA.test(b[k]));
 need(b.configurationSha256===s.files.find(r=>r.name==='public-runtime.json').sha256&&b.seedArtifactSha256===s.files.find(r=>r.name==='public-seed.archipelago').sha256&&b.publicationScopeSha256===s.files.find(r=>r.name==='public-publication-scope.json').sha256);
 need(exact(b.listener,['host','port'])&&b.listener.host==='0.0.0.0'&&Number.isSafeInteger(b.listener.port)&&b.listener.port>=1&&b.listener.port<=65535&&b.startupExpiresAt===challenge.expiresAt);
 originalWindow(value,challenge,now);return Object.freeze({value:structuredClone(value),sha256:sha(Buffer.from(canonical(value)))});
}
export function verifyActivation(envelope,{trust,challenge,ready},now=Date.now()){
 need(trust.launchCommand!==null);
 const raw=Buffer.from(canonical(envelope)),v=signed(raw,ACTIVATION_ENVELOPE,ACTIVATION_DOMAIN,trust.launchCommand.key,4096);
 need(exact(v,['schema','requestId','nonce','heldReadySha256','binding','committedPublicationSha256','controlDefinitionSha256','releaseDefinitionSha256','issuedAt','expiresAt'])&&v.schema===ACTIVATION_DOMAIN);
 need(typeof v.requestId==='string'&&v.requestId.length===36&&UUID.test(v.requestId)&&v.nonce===challenge.nonce&&v.heldReadySha256===ready.sha256&&canonical(v.binding)===canonical(ready.value.binding));
 for(const k of ['committedPublicationSha256','controlDefinitionSha256','releaseDefinitionSha256'])need(typeof v[k]==='string'&&v[k].length===64&&SHA.test(v[k]));
 originalWindow(v,challenge,now);need(now<Date.parse(ready.value.expiresAt)&&Date.parse(v.expiresAt)<=Date.parse(ready.value.expiresAt));
 return Object.freeze({body:structuredClone(v),sha256:sha(raw)});
}
export function encodeFrame(value){const raw=Buffer.from(canonical(value));need(raw.length>0&&raw.length<=32768);const size=Buffer.alloc(4);size.writeUInt32BE(raw.length);return Buffer.concat([size,raw]);}
export function frameDecoder(deliver){
 let pending=Buffer.alloc(0),count=0;
 const accept=chunk=>{need(Buffer.isBuffer(chunk)&&pending.length+chunk.length<=65544);pending=Buffer.concat([pending,chunk]);
  while(pending.length>=4){const size=pending.readUInt32BE();need(size>0&&size<=32768);if(pending.length<4+size)break;
   need(++count<=6);const value=parseCanonical(pending.subarray(4,4+size));pending=pending.subarray(4+size);deliver(value);
  }
 };accept.finish=()=>need(pending.length===0);return accept;
}
export const WORKER_FAILURE_SCHEMA='amz.ap.public-beta.production-bootstrap-worker-failure.v1';
const WORKER_STAGES=Object.freeze(['capture_inputs','challenge','seal_verify','snapshot','handoff','native_inputs','native_init','native_loop','cleanup']);
const NODE_STAGES=Object.freeze(['capture_inputs','spawn','challenge','seal_verify','native_init','native_loop','cleanup']);
/** Diagnostic data only. Any mixed/arbitrary stderr becomes unknown; no bytes
 * or parsed fields escape except the closed static stage enum. */
export function workerFailureDecoder(){
 let raw=Buffer.alloc(0),invalid=false,done=false,result='unknown';
 return Object.freeze({push(chunk){
  if(done||invalid)return;
  if(!Buffer.isBuffer(chunk)||raw.length+chunk.length>256){invalid=true;raw.fill(0);raw=Buffer.alloc(0);return;}
  const previous=raw;raw=Buffer.concat([previous,chunk]);previous.fill(0);
 },finish(){
  if(done)return result;done=true;
  try{if(invalid||raw.length===0)return result;const text=new TextDecoder('utf-8',{fatal:true}).decode(raw),v=JSON.parse(text);
   if(Buffer.from(text).equals(raw)&&canonical(v)+'\n'===text&&exact(v,['schema','stage','code'])&&v.schema===WORKER_FAILURE_SCHEMA&&v.code==='bootstrap_refused'&&WORKER_STAGES.includes(v.stage))result=v.stage;
  }catch{}finally{raw.fill(0);raw=Buffer.alloc(0);}return result;
 }});
}
export function redactedRuntimeFailure(stage,workerStage,exitCode){
 return Object.freeze({schema:'amz.ap.public-beta.production-bootstrap-runtime-failure.v1',code:'bootstrap_refused',
  stage:NODE_STAGES.includes(stage)?stage:'unknown',workerStage:WORKER_STAGES.includes(workerStage)?workerStage:'unknown',
  workerExitCode:Number.isInteger(exitCode)&&exitCode>=0&&exitCode<=255?exitCode:null});
}
async function regular(file,maximum){
 const named=await lstat(file,{bigint:true});need(named.isFile()&&!named.isSymbolicLink()&&named.nlink===1n&&named.uid===0n&&named.gid===0n&&(named.mode&0o022n)===0n&&named.size>0n&&named.size<=BigInt(maximum));
 const fd=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const before=await fd.stat({bigint:true}),raw=Buffer.alloc(maximum+1);let bytes=0;while(bytes<raw.length){const r=await fd.read(raw,bytes,raw.length-bytes,bytes);bytes+=r.bytesRead;if(!r.bytesRead)break;}
  const after=await fd.stat({bigint:true}),last=await lstat(file,{bigint:true});need(bytes===Number(before.size)&&['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs'].every(k=>named[k]===before[k]&&before[k]===after[k]&&after[k]===last[k]));return raw.subarray(0,bytes);
 }finally{await fd.close();}
}
async function fixedDirectory(file){for(let at=file;;){const s=await lstat(at);need(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===0&&s.gid===0&&(s.mode&0o022)===0);const parent=path.dirname(at);if(at===parent)break;at=parent;}need(await realpath(file)===file);}
async function inputs(){
 await fixedDirectory(OWNED);await fixedDirectory(PARENT);
 const profileRaw=await regular(OWNED+'/runtime-profile.json',65536);need(sha(profileRaw)===PROFILE_SHA);
 const profile=JSON.parse(profileRaw),artifactRaw=await regular(OWNED+'/bootstrap-artifact.json',32768),artifact=parseCanonical(artifactRaw);
 need(profile.schema==='amz.ap.public-beta.yacht-first-start-runtime-profile.v1'&&profile.profileId==='public-yacht-first-start-fresh-v1'&&profile.bootstrap.workspaceBytes===81920&&exact(artifact,['schema','version','producerCommit','profileSha256','native','ownedFiles','qualification'])&&artifact.schema==='amz.ap.public-beta.yacht-first-start-artifact.v1'&&artifact.version===1&&artifact.profileSha256===PROFILE_SHA&&canonical(artifact.native)===canonical(profile.native));
 need(typeof artifact.producerCommit==='string'&&/^[a-f0-9]{40}$/.test(artifact.producerCommit)&&exact(artifact.qualification,['sourceOnly','issuerEnrolled','providerEnrolled','productionRegistered','activation','gameplay'])&&artifact.qualification.sourceOnly===true&&Object.entries(artifact.qualification).every(([k,v])=>k==='sourceOnly'||v===false));
 const expected=['bootstrap.py','first_start.py','launcher.mjs','native_loader.py','runtime-profile.json','trust-profile.json'];need(Array.isArray(artifact.ownedFiles)&&artifact.ownedFiles.length===6&&artifact.ownedFiles.every((r,i)=>exact(r,['path','sha256','bytes'])&&r.path===expected[i]&&typeof r.sha256==='string'&&SHA.test(r.sha256)&&Number.isSafeInteger(r.bytes)&&r.bytes>0&&r.bytes<=262144));
 for(const row of artifact.ownedFiles){const raw=await regular(OWNED+'/'+row.path,262144);need(raw.length===row.bytes&&sha(raw)===row.sha256);}
 const nativeRaw=await regular(PARENT+'/public-yacht-publication-runtime.v1.json',1048576);need(sha(nativeRaw)===profile.native.artifactSha256);
 const native=JSON.parse(nativeRaw);need(native.sourceCommit===profile.native.sourceCommit&&native.executionProfileSha256===profile.native.profileSha256&&Array.isArray(native.ownedFiles)&&native.ownedFiles.length===22);
 const names=new Set();for(const row of native.ownedFiles){need(typeof row.path==='string'&&/^[A-Za-z0-9_.-]+$/.test(row.path)&&!names.has(row.path)&&typeof row.sha256==='string'&&SHA.test(row.sha256)&&Number.isSafeInteger(row.bytes)&&row.bytes>0&&row.bytes<=262144);names.add(row.path);const raw=await regular(PARENT+'/'+row.path,262144);need(raw.length===row.bytes&&sha(raw)===row.sha256);}
 const trust=publicTrust(await regular(OWNED+'/trust-profile.json',4096));return {profile,trust,artifactSha256:sha(artifactRaw)};
}
export async function main(){
 const began=process.hrtime.bigint(),startedWall=Date.now(),deadline=began+30000000000n;let wallFloor=startedWall,initialized=false,activated=false,stopping=false,failed=false,child,bootTimer,killTimer,challenge,verified,ready,activation,readyDeadline,activationDeadline,sequence=0,closed=false,closedCode=null;
 const diagnostic=workerFailureDecoder();let diagnosticStage='capture_inputs',outcome=1;
 const current=()=>{const wall=Date.now();need(!stopping&&wall>=wallFloor&&(activated||(process.hrtime.bigint()<deadline&&wall<startedWall+30000)));wallFloor=wall;return wall;};
 const stop=()=>{if(stopping)return;stopping=true;if(child&&child.exitCode===null&&child.signalCode===null){child.kill('SIGTERM');killTimer??=setTimeout(()=>{failed=true;child.kill('SIGKILL');},15000);}};
 const settle=async()=>{if(!child||closed)return;stop();const end=process.hrtime.bigint()+17000000000n;while(!closed&&process.hrtime.bigint()<end)await new Promise(resolve=>setTimeout(resolve,10));if(!closed){failed=true;child.kill('SIGKILL');for(const stream of child.stdio)stream?.destroy();child.unref();throw Error('bootstrap_worker_close_unknown');}};
 process.on('SIGTERM',stop);process.on('SIGINT',stop);
 try{
  need(process.platform==='linux'&&process.getuid()===65532&&process.getgid()===65532&&process.pid===1&&process.version==='v24.20.0');
  const admitted=await inputs();current();
  diagnosticStage='spawn';
  child=spawn('/usr/local/bin/python',['-I','-B',OWNED+'/bootstrap.py'],{shell:false,cwd:'/home/container',env:{PATH:'/usr/local/bin:/usr/bin:/bin',LANG:'C.UTF-8',TZ:'UTC',PYTHONDONTWRITEBYTECODE:'1'},stdio:['ignore','pipe','pipe','pipe','pipe']});
  diagnosticStage='challenge';
  child.once('close',code=>{closed=true;closedCode=code;});child.on('error',()=>{failed=true;stop();});
  bootTimer=setTimeout(()=>{if(!activated){failed=true;stop();}},Math.max(1,Number((deadline-process.hrtime.bigint())/1000000n)));
  let output=0;const drain=chunk=>{output+=chunk.length;if(output>2097152){failed=true;stop();}};
  child.stdout.on('data',drain);child.stderr.on('data',chunk=>{drain(chunk);diagnostic.push(chunk);});
  const reply=(seq,kind,body)=>{current();need(!child.stdio[4].destroyed&&child.stdio[4].writableLength<65536);child.stdio[4].write(encodeFrame({schema:CHANNEL,direction:'parent-to-worker',sequence:seq,kind,body}));current();};
  const decode=frameDecoder(frame=>{
   try{current();need(exact(frame,['schema','direction','sequence','kind','body'])&&frame.schema===CHANNEL&&frame.direction==='worker-to-parent'&&frame.sequence===sequence++);
    if(frame.sequence===0){need(frame.kind==='challenge');challenge=frame.body;need(exact(challenge,['schema','nonce','process','bootstrapArtifactSha256','profileSha256','nativeRoot','bootstrapRoot','issuedAt','expiresAt'])&&challenge.schema==='amz.ap.public-beta.production-bootstrap-challenge.v1'&&typeof challenge.nonce==='string'&&SHA.test(challenge.nonce)&&rootIdentity(challenge.nativeRoot)&&rootIdentity(challenge.bootstrapRoot)&&challenge.profileSha256===PROFILE_SHA&&challenge.bootstrapArtifactSha256===admitted.artifactSha256&&exact(challenge.process,['pid1StartTicks','workerStartTicks','workerPid'])&&decimal(challenge.process.pid1StartTicks)&&decimal(challenge.process.workerStartTicks)&&challenge.process.workerPid===child.pid&&instant(challenge.issuedAt)&&instant(challenge.expiresAt)&&Date.parse(challenge.issuedAt)<=Date.now()&&Date.now()<Date.parse(challenge.expiresAt)&&Date.parse(challenge.expiresAt)<=startedWall+30000&&Date.parse(challenge.expiresAt)-Date.parse(challenge.issuedAt)<=30000);reply(0,'challenge-accepted',{nonce:challenge.nonce,challengeSha256:sha(Buffer.from(canonical(challenge)))});diagnosticStage='seal_verify';
    }else if(frame.sequence===1){need(frame.kind==='verify-seal');const b=frame.body;need(challenge&&exact(b,['requestId','nonce','sealBase64'])&&typeof b.requestId==='string'&&UUID.test(b.requestId)&&b.nonce===challenge.nonce&&typeof b.sealBase64==='string');const raw=Buffer.from(b.sealBase64,'base64');need(raw.toString('base64')===b.sealBase64);verified=verifySeal(raw,{...admitted,challenge},current());current();reply(1,'seal-verified',{requestId:b.requestId,nonce:challenge.nonce,sealSha256:verified.sealSha256,bodySha256:verified.bodySha256,signerSpkiSha256:admitted.trust.issuer.rootSpkiSha256});diagnosticStage='native_init';
    }else if(frame.sequence===2){need(frame.kind==='initialized'&&verified&&exact(frame.body,['nonce','sealSha256','firstJournalSha256'])&&frame.body.nonce===challenge.nonce&&frame.body.sealSha256===verified.sealSha256&&typeof frame.body.firstJournalSha256==='string'&&SHA.test(frame.body.firstJournalSha256));current();reply(2,'initialized-accepted',{nonce:challenge.nonce,sealSha256:verified.sealSha256});initialized=true;diagnosticStage='native_loop';
    }else if(frame.sequence===3){need(initialized&&frame.kind==='held-ready');const mono=process.hrtime.bigint(),wall=current();ready=verifyHeldReady(frame.body,{challenge,verified,artifactSha256:admitted.artifactSha256},wall);readyDeadline=mono+BigInt(Date.parse(ready.value.expiresAt)-wall)*1000000n;current();need(process.hrtime.bigint()<readyDeadline);reply(3,'held-ready-accepted',{nonce:challenge.nonce,heldReadySha256:ready.sha256});
    }else if(frame.sequence===4){const b=frame.body;need(frame.kind==='verify-activation'&&ready&&process.hrtime.bigint()<readyDeadline&&exact(b,['requestId','nonce','heldReadySha256','activation'])&&b.nonce===challenge.nonce&&b.heldReadySha256===ready.sha256);const mono=process.hrtime.bigint(),wall=current();activation=verifyActivation(b.activation,{trust:admitted.trust,challenge,ready},wall);activationDeadline=mono+BigInt(Date.parse(activation.body.expiresAt)-wall)*1000000n;if(readyDeadline<activationDeadline)activationDeadline=readyDeadline;need(b.requestId===activation.body.requestId);current();need(process.hrtime.bigint()<activationDeadline);reply(4,'activation-verified',{requestId:b.requestId,nonce:challenge.nonce,heldReadySha256:ready.sha256,activationSha256:activation.sha256});
    }else{const b=frame.body;need(frame.sequence===5&&frame.kind==='activated'&&activation&&process.hrtime.bigint()<activationDeadline&&exact(b,['nonce','activationSha256','heldReadySha256','journalSha256'])&&b.nonce===challenge.nonce&&b.activationSha256===activation.sha256&&b.heldReadySha256===ready.sha256&&typeof b.journalSha256==='string'&&b.journalSha256.length===64&&SHA.test(b.journalSha256));current();need(current()<Date.parse(activation.body.expiresAt));reply(5,'activated-accepted',{nonce:challenge.nonce,activationSha256:activation.sha256});activated=true;clearTimeout(bootTimer);child.stdio[4].end();}
   }catch{failed=true;stop();}
  });
  child.stdio[3].on('data',chunk=>{try{decode(chunk);}catch{failed=true;stop();}});
  child.stdio[3].on('end',()=>{try{decode.finish();if(!activated&&!closed){failed=true;stop();}}catch{failed=true;stop();}});
  child.stdio[3].on('error',()=>{failed=true;stop();});child.stdio[4].on('error',()=>{if(!activated){failed=true;stop();}});
  reply(-1,'startup-bound',{issuedAt:new Date(startedWall).toISOString(),expiresAt:new Date(startedWall+30000).toISOString()});
  while(!closed){if(!activated){try{current();}catch{failed=true;stop();}}await new Promise(resolve=>setTimeout(resolve,10));if(stopping)await settle();}
  outcome=!failed&&activated&&closedCode===0?0:1;return outcome;
 }catch{failed=true;try{await settle();}catch{diagnosticStage='cleanup';process.exitCode=1;}return 1;}finally{
  clearTimeout(bootTimer);clearTimeout(killTimer);process.removeListener('SIGTERM',stop);process.removeListener('SIGINT',stop);
  const workerStage=diagnostic.finish();if(outcome!==0)try{process.stderr.write(canonical(redactedRuntimeFailure(diagnosticStage,workerStage,closedCode))+'\n');}catch{}
 }
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))void main().then(code=>{process.exitCode=code;}).catch(()=>{process.exitCode=1;});
