import {execFileSync} from 'node:child_process';
import {realpathSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

export function verifyContext(value) {
  if(value.repository!=='Antimatter-Zone/DMS-Archipelago-Server'||value.ref!=='refs/heads/codex/public-disposable-beta'||
     !['push','workflow_dispatch'].includes(value.event)||typeof value.sha!=='string'||!/^[a-f0-9]{40}$/.test(value.sha)||value.head!==value.sha||
     value.platform!=='linux'||value.node!=='v24.20.0'||value.uid!==1001||value.python!=='3.12')throw Error('public_source_context_rejected');
  return {schema:'amz.ap.public-beta.source-context.v1',repository:value.repository,sourceCommit:value.sha,node:value.node,python:value.python,
    engineImported:false,imageBuilt:false,nativeAccepted:false,published:false};
}
function main() {
  const environment=Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.toUpperCase().startsWith('GIT_')));
  Object.assign(environment,{GIT_NO_REPLACE_OBJECTS:'1',GIT_NO_LAZY_FETCH:'1',GIT_ALLOW_PROTOCOL:''});
  const command=(file,args)=>execFileSync(file,args,{env:environment,shell:false,encoding:'utf8',timeout:10000,maxBuffer:1024*1024}).trim();
  if(!process.env.GITHUB_WORKSPACE||realpathSync(process.env.GITHUB_WORKSPACE)!==realpathSync(process.cwd()))throw Error('public_source_workspace_rejected');
  const result=verifyContext({repository:process.env.GITHUB_REPOSITORY,ref:process.env.GITHUB_REF,event:process.env.GITHUB_EVENT_NAME,
    sha:process.env.GITHUB_SHA,head:command('git',['-c','core.fsmonitor=false','rev-parse','HEAD']),platform:process.platform,node:process.version,uid:process.getuid(),
    python:command('python3',['-I','-B','-c','import sys;print("%s.%s"%sys.version_info[:2])'])});
  console.log(JSON.stringify(result));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main();
