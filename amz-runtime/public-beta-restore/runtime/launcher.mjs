// Fixed Server-owned Public entrypoint. Protected configuration, never argv,
// nominates an independently admitted artifact. No sibling/runtime download.
import {createHash} from 'node:crypto';
import {constants} from 'node:fs';
import {lstat,open,realpath} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {Transform} from 'node:stream';
import {StringDecoder} from 'node:string_decoder';

const ROOT='/home/container/.amz',OWNED='/opt/amz-ap-public';
const PROFILE='b551c4f467b1c4d0e80dd6f0e2874050fee794343f38fe2e3a2bc8c8712965e9';
const WORLD_PACK='cb3653610aa43b893508a9f014e6a420ca6aea73e344a0738ee6722806bd2a4a',RESTORE_PROFILE='e573463a5f570e607c0d14289a2e47e5f1715b9c7960d61546ddd147accdb414';
const FOUNDATION='72b31594894b6e0d2ef0306adab965ff6e9c4fd4ec515149dc6767f356cd0a50';
const FILES=['gateway_barrier.py','gateway_hooks.py','native_files.py','checkpoint_custody.py','native_checkpoint.py','native_restore.py','native-restore-profile.v1.json','fresh-runtime-profile.json','loader.py','launcher.mjs','portal-source-manifest.json','runtime-profile.json','source-transfer.v1.json'].sort();
const sha=raw=>createHash('sha256').update(raw).digest('hex');
const need=(ok,code)=>{if(!ok)throw Error(code);};
const exact=(value,keys)=>!!value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const decode=raw=>new TextDecoder('utf-8',{fatal:true}).decode(raw);
const canonical=value=>JSON.stringify(value,(_key,item)=>item&&typeof item==='object'&&!Array.isArray(item)?Object.fromEntries(Object.keys(item).sort().map(key=>[key,item[key]])):item);
export function validateArtifact(raw,expected) {
  need(digest(expected)&&sha(raw)===expected,'public_artifact_pin_changed');
  const value=JSON.parse(decode(raw));
  need(exact(value,['schema','version','repository','sourceCommit','profileId','composition','imageRepository','engine','ownedFiles','toolchain','sourceTransfer','qualification','executionProfileSha256','nativeRestoreProfileSha256','sourceFoundation'])&&value.schema==='amz.ap.public-beta.server-runtime-restore.v1'&&value.version===1&&value.repository==='Antimatter-Zone/DMS-Archipelago-Server'&&typeof value.sourceCommit==='string'&&/^[a-f0-9]{40}$/.test(value.sourceCommit)&&value.profileId==='public-native-restricted-restore-v1'&&value.composition==='server-headless-public-slot-gateway-v1'&&value.imageRepository==='docker.darkmatterservers.com/dms-public-beta/ap-runtime-public-beta','public_artifact_rejected');
  need(value.engine?.commit==='54803be064fc7e80c4628777ed0b46a9390f255f'&&value.engine.inventorySha256==='ea87c2f934bb559c64deeb76cf61253fdbb0d12b975de02929e18d97d508f54f'&&value.engine.worldPackSha256===WORLD_PACK&&value.executionProfileSha256===PROFILE&&value.nativeRestoreProfileSha256===RESTORE_PROFILE&&sha(Buffer.from(canonical(value.sourceFoundation)))===FOUNDATION,'public_engine_pin_changed');
  need(Array.isArray(value.ownedFiles)&&value.ownedFiles.length===FILES.length&&value.ownedFiles.every((row,i)=>exact(row,['path','sha256','bytes'])&&row.path===FILES[i]&&digest(row.sha256)&&Number.isSafeInteger(row.bytes)&&row.bytes>0&&row.bytes<=262144),'public_owned_inventory_rejected');
  need(exact(value.qualification,['sourceOnly','engineImported','imageBuilt','nativeAcceptance','restartBaselineMigration','restore','fenceReopen','gameplay','productionRegistered'])&&value.qualification.sourceOnly===true&&Object.entries(value.qualification).every(([key,enabled])=>key==='sourceOnly'||enabled===false),'public_qualification_rejected');
  return value;
}
async function directory(file,privateRoot=false) {
  for(let current=file;;){const entry=await lstat(current);need(entry.isDirectory()&&!entry.isSymbolicLink(),'public_path_rejected');const parent=path.dirname(current);if(parent===current)break;current=parent;}
  need(await realpath(file)===file,'public_path_rejected');
  if(privateRoot){const info=await lstat(file);need(info.uid===process.getuid()&&(info.mode&0o777)===0o700,'public_private_directory_rejected');}
}
async function regular(file,maximum,privateFile=false) {
  await directory(path.dirname(file),privateFile);const entry=await lstat(file,{bigint:true});
  need(entry.isFile()&&!entry.isSymbolicLink()&&entry.nlink===1n&&entry.size>0n&&entry.size<=BigInt(maximum),'public_file_rejected');
  if(privateFile)need(entry.uid===BigInt(process.getuid())&&(entry.mode&0o777n)===0o600n,'public_private_file_rejected');
  const fd=await open(file,constants.O_RDONLY|(constants.O_NOFOLLOW??0)|(constants.O_NONBLOCK??0));
  try {
    const before=await fd.stat({bigint:true});need(before.dev===entry.dev&&before.ino===entry.ino,'public_file_changed');
    const raw=Buffer.alloc(maximum+1);let size=0;
    while(size<raw.length){const read=await fd.read(raw,size,raw.length-size,size);size+=read.bytesRead;if(!read.bytesRead)break;}
    const after=await fd.stat({bigint:true}),final=await lstat(file,{bigint:true}),same=value=>['dev','ino','size','mtimeNs','ctimeNs','nlink','mode','uid'].every(key=>value[key]===before[key]);
    need(size<=maximum&&BigInt(size)===before.size&&same(after)&&same(final),'public_file_changed');return Buffer.from(raw.subarray(0,size));
  }finally{await fd.close();}
}

export class RedactedLines extends Transform {
  constructor(secrets=[]){super();this.secrets=[...secrets].filter(Boolean).sort((a,b)=>b.length-a.length);this.pending='';this.dropping=false;this.decoder=new StringDecoder('utf8');}
  redact(value){for(const secret of this.secrets)value=value.split(secret).join('[REDACTED]');return value.replace(/amz1_[a-f0-9-]{36}_[A-Za-z0-9_-]{43}/g,'[REDACTED]').replace(/(Password:\s*|--password(?:=|\s+)|Bearer\s+)[^\r\n\s)]+/gi,'$1[REDACTED]');}
  accept(text){
    this.pending+=text;
    for(;;){const end=this.pending.indexOf('\n');if(end<0)break;const line=this.pending.slice(0,end+1);this.pending=this.pending.slice(end+1);
      if(!this.dropping&&Buffer.byteLength(line)<=65536)this.push(this.redact(line));else if(!this.dropping)this.push('[runtime output omitted]\n');this.dropping=false;
    }
    if(Buffer.byteLength(this.pending)>65536){if(!this.dropping)this.push('[runtime output omitted]\n');this.pending='';this.dropping=true;}
  }
  _transform(chunk,_encoding,done){try{this.accept(this.decoder.write(chunk));done();}catch{done(Error('public_log_redaction_failed'));}}
  _flush(done){try{this.accept(this.decoder.end());if(this.pending&&!this.dropping)this.push(this.redact(this.pending));done();}catch{done(Error('public_log_redaction_failed'));}}
}

async function main() {
  need(process.version==='v24.20.0'&&process.platform==='linux'&&process.getuid()!==0,'public_runtime_platform_rejected');
  const config=JSON.parse(decode(await regular(ROOT+'/public-runtime.json',16384,true)));
  need(config.schema==='amz.ap.public-beta.native-restore-configuration.v1'&&config.profileId==='public-native-restricted-restore-v1'&&config.journalMode==='migrate'&&[config.runtimeArtifactSha256,config.requiredCheckpointSha256,config.requiredMigrationSha256,config.oldStopReceiptSha256].every(digest)&&typeof config.password==='string'&&/^[A-Za-z0-9_-]{32,128}$/.test(config.password),'public_configuration_rejected');
  const artifact=validateArtifact(await regular(OWNED+'/public-server-runtime-restore.v1.json',1048576),config.runtimeArtifactSha256);
  for(const row of artifact.ownedFiles){const raw=await regular(OWNED+'/'+row.path,262144);need(raw.length===row.bytes&&sha(raw)===row.sha256,'public_owned_source_changed');}
  need(sha(await regular(OWNED+'/runtime-profile.json',65536))===PROFILE,'public_profile_changed');
  need(sha(await regular(OWNED+'/fresh-runtime-profile.json',65536))===WORLD_PACK&&sha(await regular(OWNED+'/native-restore-profile.v1.json',65536))===RESTORE_PROFILE,'public_profile_changed');
  const child=spawn('/usr/local/bin/python',['-I','-B',OWNED+'/loader.py'],{shell:false,stdio:['ignore','pipe','pipe'],cwd:'/home/container',env:{PATH:'/usr/local/bin:/usr/bin:/bin',LANG:'C.UTF-8',TZ:'UTC',PYTHONDONTWRITEBYTECODE:'1'}});
  const stdout=new RedactedLines([config.password]),stderr=new RedactedLines([config.password]);
  const stop=signal=>{if(child.exitCode===null&&child.signalCode===null)child.kill(signal);};
  const term=()=>stop('SIGTERM'),interrupt=()=>stop('SIGINT');process.once('SIGTERM',term);process.once('SIGINT',interrupt);
  const failed=()=>{process.stderr.write('Public native child transport failed.\n');stop('SIGTERM');process.exitCode=1;};
  stdout.on('error',failed);stderr.on('error',failed);child.once('error',failed);
  child.stdout.pipe(stdout).pipe(process.stdout);child.stderr.pipe(stderr).pipe(process.stderr);
  await new Promise(resolve=>child.once('close',(code)=>{process.exitCode=code??1;resolve();}));
  process.removeListener('SIGTERM',term);process.removeListener('SIGINT',interrupt);
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))void main().catch(()=>{process.stderr.write('Public native runtime refused startup.\n');process.exitCode=1;});
