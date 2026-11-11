import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {verifyContext} from './public-beta-source-preflight.mjs';

const good={repository:'Antimatter-Zone/DMS-Archipelago-Server',ref:'refs/heads/codex/public-disposable-beta',event:'push',sha:'a'.repeat(40),head:'a'.repeat(40),platform:'linux',node:'v24.20.0',uid:1001,python:'3.12'};
const guard="    if: ${{ !((github.event_name == 'push' && github.ref == 'refs/heads/codex/public-disposable-beta') || (github.event_name == 'pull_request' && github.event.pull_request.head.ref == 'codex/public-disposable-beta')) }}\n";
const source=name=>readFile(new URL('../workflows/'+name,import.meta.url),'utf8').then(raw=>raw.replaceAll('\r\n','\n'));
const sha=raw=>createHash('sha256').update(raw).digest('hex');
test('only exact Public source checkout and approved worker context receive a source-only receipt',()=>{
  assert.equal(verifyContext(good).sourceCommit,good.sha);
  assert.equal(verifyContext({...good,event:'workflow_dispatch'}).engineImported,false);
  for(const change of [{repository:'Other/Server'},{ref:'refs/heads/main'},{ref:'refs/pull/1/merge'},{event:'pull_request'},
    {sha:'b'.repeat(40)},{sha:[good.sha]},{platform:'win32'},{node:'v24.22.2'},{uid:0},{python:'3.13'}]){
    assert.throws(()=>verifyContext({...good,...change}),/context_rejected/);
  }
});
test('all source-heavy upstream jobs add only the exact push/PR-head Public exclusion',async()=>{
  const original={
    'analyze-modified-files.yml':'4f5d51bd3d24532a1e6f7c6118cc90df079fa1c89ca8e642cbe7c52a4a3a3ee1',
    'build.yml':'2e8adbad3f0278e7de721909c5a1b03915dd77fb5b8d83b53c0ec0b8420ab5f4',
    'codeql-analysis.yml':'796ebc2dc2534faf50b5d388447c1f1d2b9a26274b30d8e41c400b9162918dae',
    'ctest.yml':'82ac0f8c9d96d23afa33d5e70002358623289fafd3841fcbecc11c474e4b8079',
    'scan-build.yml':'9e3e2e35433860845ad1ff4e6513bc084124ee721875d812dc9fe8411002032c',
    'strict-type-check.yml':'596b13acd851f7c0c9e75dbd10c632dcd64a49073a67122416fe1ab455c6e56e',
    'unittests.yml':'4edb62cc2f554fff8701e862d384e656dfeeba89faa689611e6232a8ffa79d44'};
  let jobs=0;
  for(const [name,pin] of Object.entries(original)){
    const raw=await source(name),body=raw.slice(raw.indexOf('\njobs:\n'));
    for(const match of body.matchAll(/^  [\w-]+:.*\n/gm)){assert(body.slice(match.index+match[0].length).startsWith(guard),name);jobs++;}
    assert.equal(sha(raw.replaceAll(guard,'')),pin,name+' historical bytes/pins/permissions changed');
  }
  assert.equal(jobs,9);
});
test('tag publication and PR labeling remain byte-identical; no automatic Public branch publisher is added',async()=>{
  for(const [name,pin] of Object.entries({'docker.yml':'d10a11ccbef8ed36f3d0b04f83dafe3cf02ad7e2ae8eb8cd5daca18b499ae82c',
    'release.yml':'0c2ce352456053b80e549fbb4042bc0a66ecd347f640e0ab85eafa1c1c17c093',
    'label-pull-requests.yml':'14cb7768400e3892c4d952c55121776f11e19a6d36baf55e8bc2df66328ab8c4'}))assert.equal(sha(await source(name)),pin);
  const workflow=await source('public-beta-source-checks.yml');
  assert(workflow.includes("branches: ['codex/public-disposable-beta']"));
  assert(workflow.includes('actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803'));
  assert(workflow.includes('amz-source-ap-runtime-linux'));assert(workflow.includes('persist-credentials: false'));
  assert(!/--prepare|pip install|npm |docker |publish|packages:|id-token:|pull_request:/.test(workflow));
});
