// New normal PID1 entrypoint. No listener or automatic startup on import.
import {constants} from 'node:fs';
import {lstat,open,realpath} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {spawn} from 'node:child_process';

const OWNED='/opt/amz-ap-bootstrap',PARENT='/opt/amz-ap-public';
export const PROFILE_SHA='0ca69a82df3b31c931ec61d4d8116456e5bf43b672c1b41318557b74c0fcb405';
export const CHANNEL='amz.ap.public-beta.bootstrap-channel.v1';
export const DOMAIN='amz.ap.public-beta.bootstrap-seal.v1';
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
 const value=parseCanonical(raw,2048);need(exact(value,['schema','mode','rootPublicKeyPem','rootSpkiSha256'])&&value.schema==='amz.ap.public-beta.bootstrap-trust.v1');
 need(value.mode==='synthetic-qa-only'&&typeof value.rootPublicKeyPem==='string'&&value.rootPublicKeyPem.length<=512&&/^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n?$/.test(value.rootPublicKeyPem)&&typeof value.rootSpkiSha256==='string'&&SHA.test(value.rootSpkiSha256));
 const key=createPublicKey(value.rootPublicKeyPem);need(key.asymmetricKeyType==='ed25519'&&sha(key.export({type:'spki',format:'der'}))===value.rootSpkiSha256);
 return Object.freeze({...value,key});
}
export function verifySeal(raw,{profile,trust,challenge,artifactSha256},now=Date.now()){
 const envelope=parseCanonical(raw,16384);need(exact(envelope,['schema','body','signature'])&&envelope.schema==='amz.ap.public-beta.bootstrap-envelope.v1'&&typeof envelope.signature==='string');
 const signature=Buffer.from(envelope.signature,'base64');need(signature.length===64&&signature.toString('base64')===envelope.signature);
 const body=envelope.body;
 need(exact(body,['schema','sealId','operationId','nonce','challengeSha256','process','identity','native','bootstrapArtifactSha256','provider','files','issuedAt','expiresAt'])&&body.schema===DOMAIN);
 need(verify(null,Buffer.from(DOMAIN+'\n'+canonical(body)),trust.key,signature));
 need(typeof body.sealId==='string'&&UUID.test(body.sealId)&&typeof body.operationId==='string'&&UUID.test(body.operationId)&&body.nonce===challenge.nonce&&body.challengeSha256===sha(Buffer.from(canonical(challenge)))&&canonical(body.process)===canonical(challenge.process)&&body.bootstrapArtifactSha256===artifactSha256);
 need(exact(body.native,['artifactSha256','profileSha256','sourceCommit'])&&body.native.artifactSha256===profile.native.artifactSha256&&body.native.profileSha256===profile.native.profileSha256&&body.native.sourceCommit===profile.native.sourceCommit);
 const b=body.identity;need(exact(b,IDENTITY)&&b.appVariant==='public-beta'&&b.policyId==='public-disposable-beta-v1'&&['environmentId','dataEpoch','roomId','attemptId','runtimeLaunchId'].every(k=>typeof b[k]==='string'&&UUID.test(b[k]))&&['allocationRevision','seedRevision','credentialEpoch'].every(k=>Number.isSafeInteger(b[k])&&b[k]>0&&b[k]<=1000000000)&&b.externalId===`ap-beta-${b.roomId}-r${b.allocationRevision}`&&typeof b.serverId==='string'&&/^[A-Za-z0-9_-]{1,80}$/.test(b.serverId));
 const p=body.provider;need(exact(p,['serverUuid','containerId','imageId','volumeId','attestation'])&&p.attestation==='synthetic-qa-only'&&typeof p.serverUuid==='string'&&UUID.test(p.serverUuid)&&p.volumeId===p.serverUuid&&typeof p.containerId==='string'&&SHA.test(p.containerId)&&typeof p.imageId==='string'&&/^sha256:[a-f0-9]{64}$/.test(p.imageId));
 need(Array.isArray(body.files)&&body.files.length===5&&body.files.every((f,i)=>exact(f,['name','bytes','sha256','device','inode','uid','gid','mode'])&&f.name===profile.files[i].name&&Number.isSafeInteger(f.bytes)&&f.bytes>0&&f.bytes<=profile.files[i].maximumBytes&&typeof f.sha256==='string'&&SHA.test(f.sha256)&&typeof f.device==='string'&&/^[0-9]{1,10}:[0-9]{1,10}$/.test(f.device)&&decimal(f.inode)&&f.uid===65532&&f.gid===65532&&f.mode===0o600));
 need(instant(body.issuedAt)&&instant(body.expiresAt)&&Date.parse(body.issuedAt)<=now&&now<Date.parse(body.expiresAt)&&Date.parse(body.expiresAt)-Date.parse(body.issuedAt)>0&&Date.parse(body.expiresAt)-Date.parse(body.issuedAt)<=profile.bootstrap.sealMilliseconds&&Date.parse(body.expiresAt)<=Date.parse(challenge.expiresAt));
 return Object.freeze({body,sealSha256:sha(raw),bodySha256:sha(Buffer.from(canonical(body)))});
}
export function encodeFrame(value){const raw=Buffer.from(canonical(value));need(raw.length>0&&raw.length<=32768);const size=Buffer.alloc(4);size.writeUInt32BE(raw.length);return Buffer.concat([size,raw]);}
export function frameDecoder(deliver){
 let pending=Buffer.alloc(0),count=0;
 const accept=chunk=>{need(Buffer.isBuffer(chunk)&&pending.length+chunk.length<=65544);pending=Buffer.concat([pending,chunk]);
  while(pending.length>=4){const size=pending.readUInt32BE();need(size>0&&size<=32768);if(pending.length<4+size)break;
   need(++count<=3);const value=parseCanonical(pending.subarray(4,4+size));pending=pending.subarray(4+size);deliver(value);
  }
 };accept.finish=()=>need(pending.length===0);return accept;
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
 need(profile.schema==='amz.ap.public-beta.yacht-bootstrap-runtime-profile.v1'&&profile.profileId==='public-yacht-bootstrap-fresh-v1'&&exact(artifact,['schema','version','producerCommit','profileSha256','native','ownedFiles','qualification'])&&artifact.schema==='amz.ap.public-beta.yacht-bootstrap-artifact.v1'&&artifact.version===1&&artifact.profileSha256===PROFILE_SHA&&canonical(artifact.native)===canonical(profile.native));
 need(typeof artifact.producerCommit==='string'&&/^[a-f0-9]{40}$/.test(artifact.producerCommit)&&exact(artifact.qualification,['sourceOnly','issuerEnrolled','providerEnrolled','productionRegistered','activation','gameplay'])&&artifact.qualification.sourceOnly===true&&Object.entries(artifact.qualification).every(([k,v])=>k==='sourceOnly'||v===false));
 const expected=['bootstrap.py','launcher.mjs','runtime-profile.json','trust-profile.json'];need(Array.isArray(artifact.ownedFiles)&&artifact.ownedFiles.length===4&&artifact.ownedFiles.every((r,i)=>exact(r,['path','sha256','bytes'])&&r.path===expected[i]&&typeof r.sha256==='string'&&SHA.test(r.sha256)&&Number.isSafeInteger(r.bytes)&&r.bytes>0&&r.bytes<=262144));
 for(const row of artifact.ownedFiles){const raw=await regular(OWNED+'/'+row.path,262144);need(raw.length===row.bytes&&sha(raw)===row.sha256);}
 const nativeRaw=await regular(PARENT+'/public-yacht-publication-runtime.v1.json',1048576);need(sha(nativeRaw)===profile.native.artifactSha256);
 const native=JSON.parse(nativeRaw);need(native.sourceCommit===profile.native.sourceCommit&&native.executionProfileSha256===profile.native.profileSha256&&Array.isArray(native.ownedFiles)&&native.ownedFiles.length===22);
 const names=new Set();for(const row of native.ownedFiles){need(typeof row.path==='string'&&/^[A-Za-z0-9_.-]+$/.test(row.path)&&!names.has(row.path)&&typeof row.sha256==='string'&&SHA.test(row.sha256)&&Number.isSafeInteger(row.bytes)&&row.bytes>0&&row.bytes<=262144);names.add(row.path);const raw=await regular(PARENT+'/'+row.path,262144);need(raw.length===row.bytes&&sha(raw)===row.sha256);}
 const trust=publicTrust(await regular(OWNED+'/trust-profile.json',2048));return {profile,trust,artifactSha256:sha(artifactRaw)};
}
export async function main(){
 const began=process.hrtime.bigint(),startedWall=Date.now(),deadline=began+30000000000n;let wallFloor=startedWall,initialized=false,stopping=false,failed=false,child,bootTimer,killTimer,challenge,verified,sequence=0,closed=false,closedCode=null;
 const current=()=>{const wall=Date.now();need(!stopping&&wall>=wallFloor&&(initialized||process.hrtime.bigint()<deadline));wallFloor=wall;return wall;};
 const stop=()=>{stopping=true;if(child&&child.exitCode===null&&child.signalCode===null){child.kill('SIGTERM');killTimer??=setTimeout(()=>{failed=true;child.kill('SIGKILL');},15000);}};
 const settle=async()=>{if(!child||closed)return;stop();const end=process.hrtime.bigint()+17000000000n;while(!closed&&process.hrtime.bigint()<end)await new Promise(resolve=>setTimeout(resolve,10));if(!closed){failed=true;child.kill('SIGKILL');for(const stream of child.stdio)stream?.destroy();child.unref();throw Error('bootstrap_worker_close_unknown');}};
 process.on('SIGTERM',stop);process.on('SIGINT',stop);
 try{
  need(process.platform==='linux'&&process.getuid()===65532&&process.getgid()===65532&&process.pid===1&&process.version==='v24.20.0');
  const admitted=await inputs();current();
  child=spawn('/usr/local/bin/python',['-I','-B',OWNED+'/bootstrap.py'],{shell:false,cwd:'/home/container',env:{PATH:'/usr/local/bin:/usr/bin:/bin',LANG:'C.UTF-8',TZ:'UTC',PYTHONDONTWRITEBYTECODE:'1'},stdio:['ignore','pipe','pipe','pipe','pipe']});
  child.once('close',code=>{closed=true;closedCode=code;});child.on('error',()=>{failed=true;stop();});
  bootTimer=setTimeout(()=>{if(!initialized){failed=true;stop();}},Math.max(1,Number((deadline-process.hrtime.bigint())/1000000n)));
  let output=0;const drain=chunk=>{output+=chunk.length;if(output>2097152){failed=true;stop();}};
  child.stdout.on('data',drain);child.stderr.on('data',drain);
  const reply=(seq,kind,body)=>{current();need(!child.stdio[4].destroyed&&child.stdio[4].writableLength<65536);child.stdio[4].write(encodeFrame({schema:CHANNEL,direction:'parent-to-worker',sequence:seq,kind,body}));current();};
  const decode=frameDecoder(frame=>{
   try{current();need(exact(frame,['schema','direction','sequence','kind','body'])&&frame.schema===CHANNEL&&frame.direction==='worker-to-parent'&&frame.sequence===sequence++);
    if(frame.sequence===0){need(frame.kind==='challenge');challenge=frame.body;need(exact(challenge,['schema','nonce','process','bootstrapArtifactSha256','profileSha256','nativeRoot','issuedAt','expiresAt'])&&challenge.schema==='amz.ap.public-beta.bootstrap-challenge.v1'&&typeof challenge.nonce==='string'&&SHA.test(challenge.nonce)&&challenge.profileSha256===PROFILE_SHA&&challenge.bootstrapArtifactSha256===admitted.artifactSha256&&exact(challenge.process,['pid1StartTicks','workerStartTicks','workerPid'])&&decimal(challenge.process.pid1StartTicks)&&decimal(challenge.process.workerStartTicks)&&challenge.process.workerPid===child.pid&&instant(challenge.issuedAt)&&instant(challenge.expiresAt)&&Date.parse(challenge.issuedAt)<=Date.now()&&Date.now()<Date.parse(challenge.expiresAt)&&Date.parse(challenge.expiresAt)<=startedWall+30000&&Date.parse(challenge.expiresAt)-Date.parse(challenge.issuedAt)<=30000);reply(0,'challenge-accepted',{nonce:challenge.nonce,challengeSha256:sha(Buffer.from(canonical(challenge)))});
    }else if(frame.sequence===1){need(frame.kind==='verify-seal');const b=frame.body;need(challenge&&exact(b,['requestId','nonce','sealBase64'])&&typeof b.requestId==='string'&&UUID.test(b.requestId)&&b.nonce===challenge.nonce&&typeof b.sealBase64==='string');const raw=Buffer.from(b.sealBase64,'base64');need(raw.toString('base64')===b.sealBase64);verified=verifySeal(raw,{...admitted,challenge},current());current();reply(1,'seal-verified',{requestId:b.requestId,nonce:challenge.nonce,sealSha256:verified.sealSha256,bodySha256:verified.bodySha256,signerSpkiSha256:admitted.trust.rootSpkiSha256});
    }else{need(frame.sequence===2&&frame.kind==='initialized'&&verified&&exact(frame.body,['nonce','sealSha256','firstJournalSha256'])&&frame.body.nonce===challenge.nonce&&frame.body.sealSha256===verified.sealSha256&&typeof frame.body.firstJournalSha256==='string'&&SHA.test(frame.body.firstJournalSha256));current();reply(2,'initialized-accepted',{nonce:challenge.nonce,sealSha256:verified.sealSha256});initialized=true;clearTimeout(bootTimer);child.stdio[4].end();}
   }catch{failed=true;stop();}
  });
  child.stdio[3].on('data',chunk=>{try{decode(chunk);}catch{failed=true;stop();}});
  child.stdio[3].on('end',()=>{try{decode.finish();if(!initialized&&!closed){failed=true;stop();}}catch{failed=true;stop();}});
  child.stdio[3].on('error',()=>{failed=true;stop();});child.stdio[4].on('error',()=>{if(!initialized){failed=true;stop();}});
  reply(-1,'startup-bound',{issuedAt:new Date(startedWall).toISOString(),expiresAt:new Date(startedWall+30000).toISOString()});
  while(!closed){if(!initialized){try{current();}catch{failed=true;stop();}}await new Promise(resolve=>setTimeout(resolve,10));if(stopping)await settle();}
  return !failed&&initialized&&closedCode===0?0:1;
 }catch{failed=true;try{await settle();}catch{process.exitCode=1;}return 1;}finally{clearTimeout(bootTimer);clearTimeout(killTimer);process.removeListener('SIGTERM',stop);process.removeListener('SIGINT',stop);}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))void main().then(code=>{process.exitCode=code;}).catch(()=>{process.exitCode=1;});
