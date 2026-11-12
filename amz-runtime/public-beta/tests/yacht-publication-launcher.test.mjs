// Source/data fixture only: no listener, engine, image or process activation.
import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {validateArtifact} from '../../public-beta-yacht-publication/runtime/launcher.mjs';

const builder=fileURLToPath(new URL('../../public-beta-yacht-publication/build.py',import.meta.url));
const script="import importlib.util,json,sys; s=importlib.util.spec_from_file_location('fixed_publication_builder',sys.argv[1]); b=importlib.util.module_from_spec(s); s.loader.exec_module(b); print(json.dumps(b.artifact_document('1'*40,b.reviewed_source())))";
// Set ONLY by the discovered Python wrapper from its already running
// sys.executable. Never dispatch a Windows Store/PATH Python alias.
const python=process.env.AMZ_YACHT_PUBLICATION_TEST_PYTHON;
assert(typeof python==='string'&&path.isAbsolute(python),'run this fixed suite through its Python discovery wrapper');
const raw=execFileSync(python,['-I','-B','-c',script,builder],{timeout:10000,maxBuffer:2097152,windowsHide:true});
const sha=b=>createHash('sha256').update(b).digest('hex');
const encode=v=>Buffer.from(JSON.stringify(v));

test('new launcher validates the actual Python builder artifact and fixed22 inventory',()=>{
 const v=validateArtifact(raw,sha(raw));assert.equal(v.ownedFiles.length,22);
 assert.equal(v.profileId,'public-yacht-publication-fresh-v1');
 assert(v.ownedFiles.some(r=>r.path==='publication.py'));assert(v.ownedFiles.some(r=>r.path==='native_composition.py'));
 assert(v.ownedFiles.some(r=>r.path==='yacht_actions_loader.py'));assert.equal(v.qualification.sourceOnly,true);
});

test('closed profile rejects historical profiles, changed inventory and optimistic qualification',()=>{
 for(const mutate of [v=>v.schema='amz.ap.public-beta.yacht-action-runtime.v1',v=>v.profileId='public-yacht-actions-fresh-v1',
  v=>v.executionProfileSha256='0'.repeat(64),v=>v.ownedFiles.pop(),v=>v.ownedFiles.reverse(),v=>v.ownedFiles[0].path='../loader.py',
  v=>v.ownedFiles[0].untrusted=true,v=>v.qualification.gameplay=true,v=>delete v.qualification.restore,v=>v.extra=true]){
  const v=JSON.parse(raw);mutate(v);const bytes=encode(v);assert.throws(()=>validateArtifact(bytes,sha(bytes)));
 }
});

test('correct-hash BOM, invalid UTF8 and foreign hash never validate',()=>{
 for(const bytes of [Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),raw]),Buffer.from([0xff,0xfe,0x7b,0x7d])])
  assert.throws(()=>validateArtifact(bytes,sha(bytes)));
 assert.throws(()=>validateArtifact(raw,'0'.repeat(64)));
});

test('source tuple keeps independent provenance and all runtime qualification false',()=>{
 const v=validateArtifact(raw,sha(raw));assert.equal(v.sourceFoundation.sourceCommit,'80a423786d9efbce549a615bb1c297e9a1c2fd54');
 assert.equal(v.sourceFoundation.files.length,38);assert.equal(v.engine.version,'0.6.8');
 assert(Object.entries(v.qualification).every(([k,x])=>k==='sourceOnly'||x===false));
 assert(!v.ownedFiles.some(r=>r.path.includes('test')||r.path.includes('keys')));
});
