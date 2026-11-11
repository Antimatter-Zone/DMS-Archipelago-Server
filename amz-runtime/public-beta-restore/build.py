"""Separate held-restore source recipe. Default command never fetches/builds."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import types
import zipfile

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[1]
FRESH = ROOT.parent / 'public-beta'
FOUNDATION_SHA = '3a493383759174d368767d7f0b1c1f7f6f714a35819fcd94940d82196be1f3a6'
PROFILE_SHA = 'b551c4f467b1c4d0e80dd6f0e2874050fee794343f38fe2e3a2bc8c8712965e9'
RESTORE_PROFILE_SHA = 'e573463a5f570e607c0d14289a2e47e5f1715b9c7960d61546ddd147accdb414'
FRESH_BUILDER_SHA = 'b8383a1ca4cdee21c4ab2bffc6a87d9f9538a7099ff9d3d272ec73e1223e746e'
FILES = ('gateway_barrier.py', 'gateway_hooks.py', 'native_files.py', 'checkpoint_custody.py', 'native_checkpoint.py',
         'native_restore.py', 'native-restore-profile.v1.json', 'fresh-runtime-profile.json', 'loader.py', 'launcher.mjs',
         'runtime-profile.json', 'portal-source-manifest.json', 'source-transfer.v1.json')


def digest(raw): return hashlib.sha256(raw).hexdigest()


def key(file): return file.relative_to(REPOSITORY).as_posix()


def regular(file, maximum=262144):
    if not file.is_file() or file.is_symlink() or file.stat().st_nlink != 1 or not 0 < file.stat().st_size <= maximum:
        raise ValueError('restore_source_file_rejected')
    for parent in file.parents:
        if parent.is_symlink(): raise ValueError('restore_source_path_rejected')
        if parent == REPOSITORY: break
    raw = file.read_bytes()
    if len(raw) > maximum: raise ValueError('restore_source_limit')
    return raw


def reviewed_source():
    source = regular(FRESH / 'build.py')
    if digest(source) != FRESH_BUILDER_SHA: raise ValueError('restore_fresh_builder_changed')
    public = types.ModuleType('reviewed_public_fresh_builder')
    public.__file__ = str(FRESH / 'build.py')
    exec(compile(source, public.__file__, 'exec'), public.__dict__)
    base, manifest, dependencies, foundation, transfer, captured = public.reviewed_source()
    admitted = dict(captured)
    def capture(file):
        name = key(file)
        if name not in admitted: admitted[name] = regular(file)
        return admitted[name]
    provenance_raw = capture(ROOT / 'source-foundation.v1.json')
    if digest(provenance_raw) != FOUNDATION_SHA: raise ValueError('restore_foundation_changed')
    provenance = json.loads(provenance_raw)
    for row in provenance['freshFiles'] + provenance['restoreFiles']:
        if digest(capture(REPOSITORY / row['path'])) != row['sha256']: raise ValueError('restore_source_changed')
    inputs = dict(foundation)
    inputs['fresh-runtime-profile.json'] = inputs['runtime-profile.json']
    for name in ('loader.py', 'launcher.mjs', 'runtime-profile.json'):
        inputs[name] = capture(ROOT / 'runtime' / name)
    for name in ('native_restore.py', 'native-restore-profile.v1.json'):
        inputs[name] = capture(FRESH / 'runtime' / name)
    if set(inputs) != set(FILES) or digest(inputs['runtime-profile.json']) != PROFILE_SHA or digest(inputs['native-restore-profile.v1.json']) != RESTORE_PROFILE_SHA:
        raise ValueError('restore_profile_changed')
    capture(ROOT / 'build.py'); capture(ROOT / 'Dockerfile')
    return public, base, manifest, dependencies, inputs, transfer, types.MappingProxyType(admitted), provenance


def artifact_document(commit, dependencies, inputs, transfer, admitted, provenance, notices=()):
    if not re.fullmatch(r'[a-f0-9]{40}', commit): raise ValueError('restore_commit_rejected')
    # Reuse only the hash-pinned source metadata constructor, then explicitly
    # enroll the separate profile/inventory. It executes no engine code.
    source = admitted[key(FRESH / 'build.py')]
    if digest(source) != FRESH_BUILDER_SHA: raise ValueError('restore_fresh_builder_changed')
    public = types.ModuleType('reviewed_public_metadata_builder'); public.__file__ = str(FRESH / 'build.py')
    exec(compile(source, public.__file__, 'exec'), public.__dict__)
    value = public.artifact_document(commit, dependencies, inputs, transfer, admitted, notices)
    value.update(schema='amz.ap.public-beta.server-runtime-restore.v1', profileId='public-native-restricted-restore-v1',
                 executionProfileSha256=PROFILE_SHA, nativeRestoreProfileSha256=RESTORE_PROFILE_SHA, sourceFoundation=provenance)
    value['ownedFiles'] = [{'path': name, 'sha256': digest(inputs[name]), 'bytes': len(inputs[name])} for name in sorted(FILES)]
    value['toolchain'].update(dockerfileSha256=digest(admitted[key(ROOT / 'Dockerfile')]), builderSha256=digest(admitted[key(ROOT / 'build.py')]))
    return value


def prepare():
    public, base, manifest, dependencies, inputs, transfer, admitted, provenance = reviewed_source()
    commit = public.clean_commit(admitted)  # Proves these exact captured bytes.
    output = ROOT.parent / '.build'; output.mkdir(exist_ok=True)
    if output.is_symlink(): raise ValueError('restore_output_link')
    cache = output / 'public-beta-restore-cache'; cache.mkdir(exist_ok=True)
    if cache.is_symlink(): raise ValueError('restore_output_link')
    context = output / ('context-public-beta-restore-' + commit); context.mkdir()
    engine = context / 'engine'; engine.mkdir()
    archive = base.fetch('https://github.com/ArchipelagoMW/Archipelago/archive/' + base.ENGINE_COMMIT + '.zip', base.ENGINE_ARCHIVE_SHA256, 32*1024*1024, cache)
    base.extract_inventory(archive, manifest, engine); base.verify_hints(engine)
    for name, raw in inputs.items(): public.write_new(context / 'runtime' / name, raw)
    for name in ('engine-manifest.json', 'world-hints.v1.json'):
        public.write_new(context / 'runtime' / name, admitted[key(ROOT.parent / name)])
    notices = []
    for dependency in dependencies['dependencies']:
        raw = base.fetch(dependency['url'], dependency['sha256'], 16*1024*1024, cache)
        target = context / 'wheels' / dependency['url'].rsplit('/', 1)[-1]; public.write_new(target, raw)
        with zipfile.ZipFile(target) as wheel:
            for entry in wheel.infolist():
                if re.search(r'(?:^|/)(?:LICENSE[^/]*|COPYING[^/]*|NOTICE[^/]*)$', entry.filename, re.I):
                    if entry.file_size > 1048576: raise ValueError('restore_notice_limit')
                    notices.append({'dependency': dependency['name'], 'path': entry.filename, 'sha256': digest(wheel.read(entry))})
    for name in ('requirements.lock', 'dependencies.v1.json'):
        public.write_new(context / name, admitted[key(ROOT.parent / name)])
    public.write_new(context / 'Dockerfile', admitted[key(ROOT / 'Dockerfile')])
    raw = (json.dumps(artifact_document(commit, dependencies, inputs, transfer, admitted, provenance, notices), ensure_ascii=False, indent=2)+'\n').encode()
    if len(raw) > 1048576: raise ValueError('restore_artifact_limit')
    public.write_new(context / 'runtime/public-server-runtime-restore.v1.json', raw)
    public.write_new(context / 'public-server-runtime-restore.v1.json', raw)
    public.write_new(context / 'public-server-runtime-restore.v1.json.sha256', (digest(raw)+'\n').encode())
    print(json.dumps({'context': str(context), 'sourceCommit': commit, 'artifactSha256': digest(raw), 'engineImported': False, 'imageBuilt': False, 'published': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--prepare', action='store_true'); args = parser.parse_args()
    if args.prepare: prepare()
    else:
        _, _, _, dependencies, inputs, _, _, _ = reviewed_source()
        print(json.dumps({'sourceOnly': True, 'ownedFiles': len(inputs), 'pinnedWheels': len(dependencies['dependencies']), 'engineImported': False, 'imageBuilt': False, 'published': False}))
