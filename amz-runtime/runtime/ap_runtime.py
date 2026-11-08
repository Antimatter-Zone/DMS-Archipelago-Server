"""Server-owned headless integration overlay for exact AP0.6.8.

Configuration/seed/save/status locations are fixed and private. No secret argv,
runtime downloads, source updates, arbitrary shell, remote admin or file API.
"""
import asyncio, hashlib, json, logging, os, re, sys, zlib
from pathlib import Path
ENGINE=Path('/engine')
ROOT=Path('/home/container/.amz')
CONFIG=ROOT/'current.json'; SEED=ROOT/'seed.archipelago'; SAVE=ROOT/'seed.apsave'; STATUS=ROOT/'runtime-status.json'
EXPECTED_ENGINE='54803be064fc7e80c4628777ed0b46a9390f255f'
EXPECTED_PACK='ea87c2f934bb559c64deeb76cf61253fdbb0d12b975de02929e18d97d508f54f'
EXPECTED_HINTS='68e714887bfe7a867a74bc9a73d759f2b4c2e67a2e67dd0a784fa43b75dd01cc'
secrets=[]
stage='configuration'
def sanitize(value):
    for secret in sorted(set(secrets), key=len, reverse=True):
        if secret: value=value.replace(secret,'[REDACTED]')
    return re.sub(r'(Password:\s*|--password(?:=|\s+)|Bearer\s+)[^\r\n\s)]+',r'\1[REDACTED]',value,flags=re.I)
factory=logging.getLogRecordFactory()
def record_factory(*args,**kwargs):
    record=factory(*args,**kwargs); record.msg=sanitize(record.getMessage()); record.args=()
    # Tracebacks can contain arbitrary source/config strings; keep exception type only.
    if record.exc_info: record.msg+=' ['+record.exc_info[0].__name__+']';record.exc_info=None;record.exc_text=None
    return record
logging.setLogRecordFactory(record_factory)
def read_fixed(file,limit):
    if file.is_symlink() or not file.is_file() or file.stat().st_size>limit: raise ValueError('private_file_invalid')
    return file.read_bytes()
def verify_engine():
    manifest_bytes=read_fixed(Path('/opt/amz-ap/engine-manifest.json'),2*1024*1024)
    if hashlib.sha256(manifest_bytes).hexdigest()!=EXPECTED_PACK: raise ValueError('manifest_pin_mismatch')
    manifest=json.loads(manifest_bytes)
    if manifest['engineCommit']!=EXPECTED_ENGINE: raise ValueError('engine_pin_mismatch')
    for entry in manifest['files']:
        file=ENGINE/entry['path']
        if not file.resolve().is_relative_to(ENGINE.resolve()) or file.is_symlink(): raise ValueError('source_path_invalid')
        value=file.read_bytes()
        if entry['algorithm']=='sha256-lf': value=value.replace(b'\r\n',b'\n')
        if hashlib.sha256(value).hexdigest()!=entry['sha256']: raise ValueError('engine_source_changed')

def apply_world_hints(context, metadata):
    # Equivalent only for this reviewed pack. Unknown/custom packs fail closed.
    if metadata.get('schema')!='amz.ap.headless-world-hints.v1' or metadata.get('engineCommit')!=EXPECTED_ENGINE or metadata.get('worldPackSha256')!=EXPECTED_PACK or metadata.get('defaultBlacklist')!=[] or not set(context.played_games).issubset(metadata.get('allowedGames',[])):
        raise ValueError('headless_world_pack_unsupported')
    for game in context.played_games:
        context.non_hintable_names[game]=frozenset(metadata['overrides'].get(game,[]))

def controlled_world_data(context):
    value=read_fixed(Path('/opt/amz-ap/world-hints.v1.json'),65536)
    if hashlib.sha256(value).hexdigest()!=EXPECTED_HINTS:raise ValueError('headless_hint_integrity')
    apply_world_hints(context,json.loads(value))

def initialize_core_settings(module):
    # get_settings() otherwise creates host.yaml by dumping every world's
    # settings. This dedicated service accepts native core defaults plus only
    # the fixed args/embedded reviewed room rules, never a mutable host.yaml.
    module.no_gui=True;module.skip_autosave=True
    module.get_settings._cache=module.Settings(None)
def main():
    global stage
    if not Path('/.dockerenv').is_file() or os.getuid()==0: raise ValueError('nonroot_container_required')
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    if ROOT.is_symlink(): raise ValueError('private_root_invalid')
    config=json.loads(read_fixed(CONFIG,16384))
    if config['engineCommit']!=EXPECTED_ENGINE or config['worldPackSha256']!=EXPECTED_PACK or not re.fullmatch(r'[A-Za-z0-9_-]{32,128}',config['password']): raise ValueError('runtime_configuration_invalid')
    if not isinstance(config['port'],int) or not 1<=config['port']<=65535 or not isinstance(config['seedRevision'],int) or config['seedRevision']<1: raise ValueError('runtime_configuration_invalid')
    secrets.append(config['password'])
    if not re.fullmatch(r'[a-f0-9-]{36}',str(config.get('runtimeLaunchId',''))):raise ValueError('runtime_configuration_invalid')
    overlay={'schema':'amz.ap.runtime-overlay.v1','files':[{'path':name,'sha256':hashlib.sha256(read_fixed(Path('/opt/amz-ap')/name,131072)).hexdigest()} for name in ('ap_runtime.py','launcher.mjs')]}
    actual_overlay=hashlib.sha256(json.dumps(overlay,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if actual_overlay!=config['runtimeOverlaySha256']:raise ValueError('runtime_overlay_changed')
    if hashlib.sha256(read_fixed(SEED,16*1024*1024)).hexdigest()!=config['seedArtifactSha256']: raise ValueError('seed_integrity')
    stage='engine_verification';verify_engine()
    # Imports occur only after the exact container source inventory is verified.
    os.environ.clear();os.environ.update({'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':str(ROOT),'XDG_CONFIG_HOME':str(ROOT/'config'),'XDG_CACHE_HOME':str(ROOT/'cache'),'APPDATA':str(ROOT),'SKIP_REQUIREMENTS_UPDATE':'1','PYTHONDONTWRITEBYTECODE':'1'})
    stage='native_import';sys.path.insert(0,str(ENGINE));import Utils, settings
    initialize_core_settings(settings)
    for name,destination in [('user_path',ROOT),('home_path',ROOT),('cache_path',ROOT/'cache'),('output_path',ROOT/'output')]:getattr(Utils,name).cached_path=str(destination)
    import MultiServer
    # The native loader imports every executable world solely for hint metadata.
    # Use the reviewed equivalent data for this exact pack; generation stays native.
    MultiServer.Context._load_world_data=controlled_world_data
    state={'context':None,'restored':None}
    def controlled_init_save(self,enabled=True):
        global stage
        stage='checkpoint_load'
        if not enabled: raise ValueError('saving_required')
        self.save_filename=str(SAVE);self.saving=True
        required=config.get('requiredCheckpointSha256')
        if required:
            value=read_fixed(SAVE,16*1024*1024)
            actual=hashlib.sha256(value).hexdigest()
            if actual!=required: raise ValueError('checkpoint_integrity')
            saved=MultiServer.restricted_loads(zlib.decompress(value))
            old_password=saved.get('game_options',{}).get('password')
            if isinstance(old_password,str):secrets.append(old_password)
            self.set_save(saved) # Native identity/version validation; errors are fatal.
            state['restored']=actual
        elif not config.get('allowFreshSave'): raise ValueError('explicit_checkpoint_required')
        # Native saves contain old game_options.password; override only after native load.
        self.password=config['password'];self.server_password='';self.item_cheat=False
        self._start_async_saving()
        if not self.save(True): raise ValueError('initial_checkpoint_failed')
        state['context']=self
    # Keep the native class identity: its __init__ uses super(Context,self).
    MultiServer.Context.init_save=controlled_init_save
    sys.argv=['MultiServer.py',str(SEED),'--host','0.0.0.0','--port',str(config['port']),'--savefile',str(SAVE),'--use_embedded_options','--disable_item_cheat','--auto_shutdown','0','--loglevel','warning']
    args=MultiServer.parse_args();args.password=config['password'];args.server_password='';args.log_network=False;args.cert=None;args.cert_key=None
    try: revision=int(json.loads(STATUS.read_text()).get('observationRevision',0))
    except Exception: revision=0
    async def run():
        nonlocal revision
        async def observe():
            nonlocal revision
            while True:
                await asyncio.sleep(1)
                ctx=state['context']
                if ctx is None or ctx.exit_event.is_set() or not getattr(ctx.server,'ws_server',None): continue
                clients=[client for client in ctx.endpoints if client.auth and not any(tag in client.tags for tag in ('Tracker','TextOnly','HintGame'))]
                slots=[]
                for (team,slot),name in ctx.player_names.items():
                    if team!=0 or not re.fullmatch(r'[A-Za-z0-9_-]{1,16}',name): continue
                    status=ctx.client_game_state.get((team,slot))
                    slots.append({'slotAlias':name,'connected':any(client.team==team and client.slot==slot for client in clients),'completed':None if not status else int(status)==30,'checkedLocations':len(ctx.location_checks[team,slot]) if (team,slot) in ctx.location_checks else None,'totalLocations':len(ctx.locations[slot]) if slot in ctx.locations else None})
                revision+=1
                from datetime import datetime,timezone
                value={'schema':1,'state':'running','attemptId':config['attemptId'],'seedRevision':config['seedRevision'],'credentialEpoch':config['credentialEpoch'],'runtimeLaunchId':config['runtimeLaunchId'],'seedArtifactSha256':config['seedArtifactSha256'],'runtimeOverlaySha256':actual_overlay,'restoredCheckpointSha256':state['restored'],'logsRedacted':True,'connectedGameClients':len(clients),'observationRevision':revision,'observedAt':datetime.now(timezone.utc).isoformat(),'slots':slots}
                temporary=STATUS.with_suffix('.next');temporary.write_text(json.dumps(value),encoding='utf-8');temporary.chmod(0o600);temporary.replace(STATUS)
        task=asyncio.create_task(observe())
        try:await MultiServer.main(args)
        finally:task.cancel()
    stage='native_runtime';asyncio.run(run())
if __name__=='__main__':
    try:main()
    except BaseException as error:
        # Never stringify errors/config/tracebacks at the process boundary.
        trace=error.__traceback__
        while trace and trace.tb_next:trace=trace.tb_next
        if trace:
            module=str(trace.tb_frame.f_globals.get('__name__',''))
            function=trace.tb_frame.f_code.co_name
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*',module) and re.fullmatch(r'(?:[A-Za-z_][A-Za-z0-9_]*|<module>)',function):print(json.dumps({'schema':'amz.ap.runtime-diagnostic.v1','stage':stage,'exceptionType':type(error).__name__,'module':module,'function':function,'line':trace.tb_lineno}),file=sys.stderr)
        code=str(error) if isinstance(error,ValueError) and str(error) in {'private_file_invalid','private_root_invalid','runtime_configuration_invalid','runtime_overlay_changed','seed_integrity','manifest_pin_mismatch','engine_pin_mismatch','source_path_invalid','engine_source_changed','checkpoint_integrity','explicit_checkpoint_required','initial_checkpoint_failed','nonroot_container_required','headless_world_pack_unsupported','headless_hint_integrity'} else type(error).__name__
        print('AP runtime stopped: '+stage+':'+code,file=sys.stderr);raise SystemExit(1)
