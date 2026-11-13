import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {RedactedLines,validateArtifact} from '../runtime/launcher.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
const sha=raw=>createHash('sha256').update(raw).digest('hex');
function artifact() {
  const code="import importlib.util,json;from pathlib import Path;r=Path('.').resolve();s=importlib.util.spec_from_file_location('public_builder',r/'build.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);_,_,d,i,t,a=m.reviewed_source();print(json.dumps(m.artifact_document('f'*40,d,i,t,a)))";
  const environment=Object.fromEntries(Object.entries(process.env).filter(([key])=>['PATH','SYSTEMROOT','WINDIR','TEMP','TMP','LOCALAPPDATA','USERPROFILE','LANG'].includes(key.toUpperCase())));
  const result=spawnSync(process.platform==='win32'?'python':'python3',['-I','-B','-c',code],{cwd:root,env:environment,shell:false,windowsHide:true,encoding:'utf8',timeout:10000,maxBuffer:1024*1024});
  assert.equal(result.status,0,'Synthetic builtins-only artifact fixture failed');return Buffer.from(result.stdout.trim());
}
test('actual Python artifact is consumed by Node only under an independent exact SHA and closed Public schema',()=>{
  const raw=artifact(),value=validateArtifact(raw,sha(raw));assert.equal(value.profileId,'public-disposable-beta-v1');
  for(const change of ['pin','member','path','claim','commit_type']) {
    const candidate=structuredClone(value);if(change==='member')candidate.schema='amz.ap.server-runtime.v1';
    if(change==='path')candidate.ownedFiles[0].path='../loader.py';if(change==='claim')candidate.qualification.nativeAcceptance=true;
    if(change==='commit_type')candidate.sourceCommit=[candidate.sourceCommit];
    const bytes=Buffer.from(JSON.stringify(candidate));assert.throws(()=>validateArtifact(bytes,change==='pin'?'0'.repeat(64):sha(bytes)));
  }
});
test('streaming public redaction covers split master/proof and suppresses the entire oversized line tail',async()=>{
  const master='synthetic_private_master_'+'x'.repeat(40),proof='amz1_11111111-1111-1111-1111-111111111111_'+'P'.repeat(43);
  const stream=new RedactedLines([master]);let output='';stream.on('data',chunk=>{output+=chunk.toString();});
  stream.write(master.slice(0,13));stream.write(master.slice(13)+' '+proof.slice(0,25));stream.write(proof.slice(25)+'\n');
  stream.write('x'.repeat(65537));stream.write('SYNTHETIC_PRIVATE_TAIL\n');stream.end('safe final');
  await new Promise(resolve=>stream.once('end',resolve));
  assert(!output.includes(master));assert(!output.includes(proof));assert(!output.includes('SYNTHETIC_PRIVATE_TAIL'));assert(output.includes('[runtime output omitted]'));assert(output.endsWith('safe final'));
});
test('Public launcher has fixed verified paths, no secret argv/environment and no legacy fallback',async()=>{
  const source=await readFile(new URL('../runtime/launcher.mjs',import.meta.url),'utf8');
  assert(source.includes("spawn('/usr/local/bin/python',['-I','-B',OWNED+'/loader.py']"));assert(source.includes("shell:false"));
  assert(!/process\.env|fetch\(|exec\(|current\.json'|\/opt\/amz-ap\//.test(source));
  assert(source.indexOf('const artifact=validateArtifact')<source.indexOf("const child=spawn("));assert(source.indexOf('public_owned_source_changed')<source.indexOf("const child=spawn("));
});

import './yacht-first-start.test.mjs';
