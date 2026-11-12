// Separate fresh Yacht action profile. No automatic startup on import.
import {constants} from 'node:fs';
import {lstat,open,realpath} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';

const ROOT='/home/container/.amz',OWNED='/opt/amz-ap-public';
const PROFILE='7190f98fe01ed797cd43db72a7d205d22f93ef4a11a1536263ac8a886595cc72';
const FILES=['gateway_barrier.py','gateway_hooks.py','native_files.py','checkpoint_custody.py','native_checkpoint.py','loader.py','launcher.mjs',
 'portal-source-manifest.json','runtime-profile.json','source-transfer.v1.json','fresh_loader.py','fresh-runtime-profile.json','native_yacht_effects.py',
 'effects-profile.v1.json','native_yacht_observations.py','observation-profile.v1.json','yacht_packet_policy.py','native_budget.py','source-foundation.v1.json'].sort();
const need=ok=>{if(!ok)throw Error('yacht_launcher_refused');};
const sha=raw=>createHash('sha256').update(raw).digest('hex');
const digest=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
async function directory(file,privateRoot=false){
 for(let current=file;;){const info=await lstat(current);need(info.isDirectory()&&!info.isSymbolicLink());const parent=path.dirname(current);if(parent===current)break;current=parent;}
 need(await realpath(file)===file);if(privateRoot){const info=await lstat(file);need(info.uid===65532&&(info.mode&0o777)===0o700);}
}
async function regular(file,maximum,privateFile=false){
 await directory(path.dirname(file),privateFile);const entry=await lstat(file,{bigint:true});
 need(entry.isFile()&&!entry.isSymbolicLink()&&entry.nlink===1n&&entry.size>0n&&entry.size<=BigInt(maximum));
 if(privateFile)need(entry.uid===65532n&&(entry.mode&0o777n)===0o600n);
 const fd=await open(file,constants.O_RDONLY|(constants.O_NOFOLLOW??0)|(constants.O_NONBLOCK??0));
 try{const before=await fd.stat({bigint:true}),raw=Buffer.alloc(maximum+1);need(before.dev===entry.dev&&before.ino===entry.ino);let size=0;
  while(size<raw.length){const r=await fd.read(raw,size,raw.length-size,size);size+=r.bytesRead;if(!r.bytesRead)break;}
  const after=await fd.stat({bigint:true}),named=await lstat(file,{bigint:true});need(size===Number(before.size)&&size<=maximum&&['dev','ino','size','mode','uid','nlink','mtimeNs','ctimeNs'].every(k=>before[k]===after[k]&&after[k]===named[k]));return raw.subarray(0,size);
 }finally{await fd.close();}
}
export function validateArtifact(raw,expected){
 need(digest(expected)&&sha(raw)===expected);const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);need(Buffer.from(text).equals(raw));const v=JSON.parse(text);
 need(v.schema==='amz.ap.public-beta.yacht-action-runtime.v1'&&v.version===1&&v.repository==='Antimatter-Zone/DMS-Archipelago-Server'&&/^[a-f0-9]{40}$/.test(v.sourceCommit)&&
  v.profileId==='public-yacht-actions-fresh-v1'&&v.composition==='server-headless-public-yacht-actions-v1'&&v.executionProfileSha256===PROFILE&&
  v.imageRepository==='docker.darkmatterservers.com/dms-public-beta/ap-runtime-public-beta'&&v.engine?.commit==='54803be064fc7e80c4628777ed0b46a9390f255f'&&
  v.engine.inventorySha256==='ea87c2f934bb559c64deeb76cf61253fdbb0d12b975de02929e18d97d508f54f'&&v.engine.worldPackSha256==='cb3653610aa43b893508a9f014e6a420ca6aea73e344a0738ee6722806bd2a4a');
 need(Array.isArray(v.ownedFiles)&&v.ownedFiles.length===FILES.length&&v.ownedFiles.every((r,i)=>r.path===FILES[i]&&digest(r.sha256)&&Number.isSafeInteger(r.bytes)&&r.bytes>0&&r.bytes<=262144));
 need(v.qualification?.sourceOnly===true&&Object.entries(v.qualification).every(([k,x])=>k==='sourceOnly'||x===false));return v;
}
async function main(){
 need(process.platform==='linux'&&process.getuid()===65532&&process.version==='v24.20.0');
 const config=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await regular(ROOT+'/public-runtime.json',16384,true)));
 need(config.schema==='amz.ap.public-beta.yacht-native-configuration.v1'&&config.profileId==='public-yacht-actions-fresh-v1'&&config.executionProfileSha256===PROFILE);
 const artifact=validateArtifact(await regular(OWNED+'/public-yacht-runtime.v1.json',1048576),config.runtimeArtifactSha256);
 for(const row of artifact.ownedFiles){const raw=await regular(OWNED+'/'+row.path,262144);need(raw.length===row.bytes&&sha(raw)===row.sha256);}
 need(sha(await regular(OWNED+'/runtime-profile.json',65536))===PROFILE);
 let child,stopping=false,failed=false,timer;
 const stop=()=>{stopping=true;if(child&&child.exitCode===null&&child.signalCode===null){child.kill('SIGTERM');timer??=setTimeout(()=>{failed=true;child.kill('SIGKILL');},15000);}};
 process.on('SIGINT',stop);process.on('SIGTERM',stop);
 try{
  need(!stopping);child=spawn('/usr/local/bin/python',['-I','-B',OWNED+'/loader.py'],{shell:false,cwd:'/home/container',env:{PATH:'/usr/local/bin:/usr/bin:/bin',LANG:'C.UTF-8',TZ:'UTC',PYTHONDONTWRITEBYTECODE:'1'},stdio:['ignore','pipe','pipe']});
  // Native output is deliberately NOT exported or regex-redacted. Bounded
  // draining prevents pipe deadlock without leaking any key/config/packet.
  let bytes=0;const drain=chunk=>{bytes+=chunk.length;if(bytes>2097152){failed=true;stop();}};
  child.stdout.on('data',drain);child.stderr.on('data',drain);child.on('error',()=>{failed=true;stop();});
  const code=await new Promise(resolve=>child.once('close',resolve));process.exitCode=!failed&&code===0?0:1;
 }finally{clearTimeout(timer);process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))void main().catch(()=>{process.stderr.write('Yacht runtime refused startup.\n');process.exitCode=1;});
