// Server-owned headless entrypoint. No secret argv, no inherited Panel/bot credentials.
import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {Transform} from 'node:stream';
export class RedactedLines extends Transform {
  constructor(secrets=[]){super();this.secrets=secrets.filter(Boolean);this.pending='';}
  redact(value){for(const secret of this.secrets.sort((a,b)=>b.length-a.length))value=value.split(secret).join('[REDACTED]');return value.replace(/(Password:\s*|--password(?:=|\s+)|Bearer\s+)[^\r\n\s)]+/gi,'$1[REDACTED]');}
  _transform(chunk,encoding,done){this.pending+=chunk.toString('utf8');let end;while((end=this.pending.indexOf('\n'))>=0){const line=this.pending.slice(0,end+1);this.pending=this.pending.slice(end+1);this.push(this.redact(line));}if(Buffer.byteLength(this.pending)>65536){this.push('[runtime output omitted]\n');this.pending='';}done();}
  _flush(done){if(this.pending)this.push(this.redact(this.pending));done();}
}
async function main(){const config=JSON.parse(await readFile('/home/container/.amz/current.json','utf8'));const secrets=[config.password];const child=spawn('/usr/local/bin/python',['-I','-B','/opt/amz-ap/ap_runtime.py'],{shell:false,stdio:['ignore','pipe','pipe'],cwd:'/home/container',env:{PATH:'/usr/local/bin:/usr/bin:/bin',LANG:'C.UTF-8',TZ:'UTC',PYTHONDONTWRITEBYTECODE:'1'}});child.stdout.pipe(new RedactedLines(secrets)).pipe(process.stdout);child.stderr.pipe(new RedactedLines(secrets)).pipe(process.stderr);for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>child.kill(signal));child.once('error',()=>{console.error('AP runtime launch failed.');process.exitCode=1;});child.once('exit',code=>{process.exitCode=code??1;});}
if(process.argv[1]?.endsWith('/launcher.mjs'))void main().catch(()=>{console.error('AP runtime configuration unavailable.');process.exitCode=1;});
