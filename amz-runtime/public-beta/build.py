"""Check Public source or explicitly prepare a NEW immutable build context.

Default is offline/source-only. --prepare downloads pinned public inputs only;
it requires a clean committed tree and separate operator scheduling approval.
It never imports the engine, installs packages, runs Docker or publishes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import types
import zipfile

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
REPOSITORY = BASE.parent
PORTAL_COMMIT = '29a39c3431a6607b2e9faade355a92f16d6fd74f'
PROFILE_SHA = 'b7912cd11d98e026ff89701b526ccefd4ef819126bf09766aa61abb74c203269'
TRANSFER_SHA = '9c42e0921b72e8208bffbd81febf0fd207aea22c1ffe8943c613ec490046757f'
BASE_PINS = {
    'build.py': '3365b861acef7c6748d8be77d8172120418bb21f3c2633a932fb7b935617365f',
    'engine-manifest.json': 'ea87c2f934bb559c64deeb76cf61253fdbb0d12b975de02929e18d97d508f54f',
    'world-hints.v1.json': '68e714887bfe7a867a74bc9a73d759f2b4c2e67a2e67dd0a784fa43b75dd01cc',
    'dependencies.v1.json': 'aa532aef2028e184b8e805b2eb1f588773dda83aac1268112ff0d9ef3bfdd1cc',
    'requirements.lock': '9437283f9b55a808014f26b13c3a82c961b4eec5bd3685040c30dbaa79a4966b',
    'source-provenance.v1.json': 'b1842d10fbf1188f8a0709dd9173aacae151faed1676280b59201908c202e8b3',
    'runtime/ap_runtime.py': 'bb86bb90b8d3be2868558e2be84e0be6a36f765067cbac9fae95577e1cdc7639',
    'runtime/launcher.mjs': 'b87a23ed06f89f5a3a27b86145e749c78b6664b23e27d4781632098f8225decd',
}
PORTAL_PINS = {
    'runtime/gateway_barrier.py': '8f7c953249d9d646511599ff267233f617f06223951855259855693f10cee3d9',
    'runtime/gateway_hooks.py': 'dbfb8fe3ee524dfecd761d3b7c188497ab4c5f5944bf34bc025465e8dac9f8e4',
    'runtime/native_files.py': '31a06a804af044442b4b2040a8e30f4be277bbe44fe5ae544c14b38686dd9e24',
    'runtime/portal-source-manifest.json': 'e1404bf1f93bc23641c3aef46276aea8db3191d967704e6aabfc365970c49f3f',
}
FILES = ('gateway_barrier.py', 'gateway_hooks.py', 'native_files.py', 'loader.py', 'launcher.mjs',
         'portal-source-manifest.json', 'runtime-profile.json', 'source-transfer.v1.json')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(file, maximum=262144):
    info = file.lstat()
    if file.resolve() != file.absolute() or not info.st_nlink == 1 or file.is_symlink() or not file.is_file() or not 0 < info.st_size <= maximum:
        raise ValueError('public_build_input_rejected')
    raw = file.read_bytes()
    if len(raw) != info.st_size:
        raise ValueError('public_build_input_changed')
    return raw


class CapturedRoot:
    """The pinned helper reads metadata from this snapshot, never a later path."""
    def __init__(self, files, name=''):
        self.files, self.name = files, name

    def __truediv__(self, name):
        return CapturedRoot(self.files, (self.name + '/' + str(name)).lstrip('/'))

    def read_bytes(self):
        return self.files[self.name]

    def read_text(self):
        return self.read_bytes().decode('utf-8')


def key(file):
    return file.relative_to(REPOSITORY).as_posix()


def reviewed_source():
    base_bytes = {}
    for name, expected in BASE_PINS.items():
        raw = regular(BASE / name, 2 * 1024 * 1024)
        if digest(raw) != expected:
            raise ValueError('member_base_changed')
        base_bytes[name] = raw
    # Import only this hash-pinned, builtins-only source preparation helper.
    base = types.ModuleType('reviewed_member_source_builder')
    base.__file__ = str(BASE / 'build.py')
    exec(compile(base_bytes['build.py'], base.__file__, 'exec'), base.__dict__)
    base.ROOT = CapturedRoot(types.MappingProxyType(base_bytes))
    manifest, _, _, dependencies = base.reviewed_source()
    admitted = {key(BASE / name): raw for name, raw in base_bytes.items()}
    def capture(file, maximum=262144):
        name = key(file)
        if name not in admitted:
            admitted[name] = regular(file, maximum)
        return admitted[name]
    for name, expected in PORTAL_PINS.items():
        if digest(capture(ROOT / name)) != expected:
            raise ValueError('portal_transfer_changed')
    transfer_raw = capture(ROOT / 'source-transfer.v1.json')
    if digest(transfer_raw) != TRANSFER_SHA:
        raise ValueError('portal_transfer_changed')
    transfer = json.loads(transfer_raw)
    if transfer['repository'] != 'Antimatter-Zone/DMS-Archipelago-Portal' or transfer['sourceCommit'] != PORTAL_COMMIT:
        raise ValueError('portal_transfer_changed')
    for row in transfer['files']:
        if digest(capture(ROOT / row['path'])) != row['sha256'] or not re.fullmatch(r'[a-f0-9]{40}', row['sourceBlob']):
            raise ValueError('portal_transfer_changed')
        if row['path'] in PORTAL_PINS and (row['sourceSha256'] != PORTAL_PINS[row['path']] or row['transformation'] is not None):
            raise ValueError('portal_transfer_changed')
    profile = capture(ROOT / 'runtime/runtime-profile.json')
    if digest(profile) != PROFILE_SHA:
        raise ValueError('public_profile_changed')
    inputs = {name: capture(ROOT / 'runtime' / name) for name in FILES if name != 'source-transfer.v1.json'}
    inputs['source-transfer.v1.json'] = transfer_raw
    capture(ROOT / 'Dockerfile')
    capture(ROOT / 'build.py')
    return base, manifest, dependencies, inputs, transfer, types.MappingProxyType(admitted)


def artifact_document(commit, dependencies, inputs, transfer, admitted, notices=()):
    if not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise ValueError('public_source_commit_rejected')
    return {'schema': 'amz.ap.public-beta.server-runtime.v1', 'version': 1,
            'repository': 'Antimatter-Zone/DMS-Archipelago-Server', 'sourceCommit': commit, 'profileId': 'public-disposable-beta-v1',
            'composition': 'server-headless-public-slot-gateway-v1', 'imageRepository': 'docker.darkmatterservers.com/dms-public-beta/ap-runtime-public-beta',
            'engine': {'version': '0.6.8', 'commit': '54803be064fc7e80c4628777ed0b46a9390f255f',
                       'archiveSha256': '3b9c408cd43b09ab27691d5a0b8d18686cd113ebdd06fdd9606c229010648ef8',
                       'inventorySha256': BASE_PINS['engine-manifest.json'], 'worldPackSha256': PROFILE_SHA,
                       'headlessHintsSha256': BASE_PINS['world-hints.v1.json']},
            'ownedFiles': [{'path': name, 'sha256': digest(inputs[name]), 'bytes': len(inputs[name])} for name in sorted(FILES)],
            'toolchain': {'platform': 'linux/amd64', 'pythonImage': 'python:3.12-slim-bookworm@sha256:623674a14ef93d052bb9b0de4dbf5f28eb578a35263838941cc8aa43213c1487',
                          'nodeImage': 'node:24.20.0-bookworm-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e',
                          'dockerfileSha256': digest(admitted[key(ROOT / 'Dockerfile')]), 'builderSha256': digest(admitted[key(ROOT / 'build.py')]),
                          'sourceHelperSha256': BASE_PINS['build.py'], 'dependenciesSha256': BASE_PINS['dependencies.v1.json'],
                          'requirementsSha256': BASE_PINS['requirements.lock'], 'dependencies': dependencies, 'dependencyNotices': list(notices)},
            'sourceTransfer': transfer,
            'qualification': {'sourceOnly': True, 'engineImported': False, 'imageBuilt': False, 'nativeAcceptance': False,
                              'restartBaselineMigration': False, 'restore': False, 'fenceReopen': False, 'gameplay': False, 'productionRegistered': False}}


def clean_commit(admitted):
    import os
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith('GIT_')}
    environment.update(GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL='')
    def git(*args):
        result = subprocess.run(['git', '-c', 'core.fsmonitor=false', *args], cwd=REPOSITORY, env=environment,
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if len(result.stdout) > 1048576:
            raise ValueError('public_git_output_limit')
        return result.stdout
    commit = git('rev-parse', 'HEAD^{commit}').decode().strip()
    if not re.fullmatch(r'[a-f0-9]{40}', commit) or git('status', '--porcelain', '--untracked-files=all').strip():
        raise ValueError('clean_committed_source_required')
    # Prove these CAPTURED bytes against Git. Fresh working-tree rereads could
    # silently relabel an earlier dirty snapshot after it was restored to HEAD.
    for name, raw in admitted.items():
        tree = git('ls-tree', commit, '--', name).decode().split()
        if tree[:2] != ['100644', 'blob'] or git('cat-file', 'blob', commit + ':' + name) != raw:
            raise ValueError('public_git_blob_mismatch')
    return commit


def write_new(file, raw):
    if file.exists() or file.is_symlink():
        raise ValueError('public_output_exists')
    file.parent.mkdir(parents=True, exist_ok=True)
    with file.open('xb') as out:
        out.write(raw)


def prepare():
    base, manifest, dependencies, inputs, transfer, admitted = reviewed_source()
    commit = clean_commit(admitted)
    output = BASE / '.build'
    output.mkdir(exist_ok=True)
    if output.is_symlink():
        raise ValueError('public_output_link')
    cache = output / 'public-beta-cache'
    cache.mkdir(exist_ok=True)
    if cache.is_symlink():
        raise ValueError('public_output_link')
    context = output / ('context-public-beta-' + commit)
    context.mkdir()  # Preserve partial contexts and never overwrite/retry one.
    engine = context / 'engine'
    engine.mkdir()
    archive = base.fetch('https://github.com/ArchipelagoMW/Archipelago/archive/' + base.ENGINE_COMMIT + '.zip', base.ENGINE_ARCHIVE_SHA256, 32 * 1024 * 1024, cache)
    base.extract_inventory(archive, manifest, engine)
    base.verify_hints(engine)
    for name, raw in inputs.items():
        write_new(context / 'runtime' / name, raw)
    for name in ('engine-manifest.json', 'world-hints.v1.json'):
        write_new(context / 'runtime' / name, admitted[key(BASE / name)])
    notices = []
    for dependency in dependencies['dependencies']:
        raw = base.fetch(dependency['url'], dependency['sha256'], 16 * 1024 * 1024, cache)
        target = context / 'wheels' / dependency['url'].rsplit('/', 1)[-1]
        write_new(target, raw)
        with zipfile.ZipFile(target) as wheel:
            for entry in wheel.infolist():
                if re.search(r'(?:^|/)(?:LICENSE[^/]*|COPYING[^/]*|NOTICE[^/]*)$', entry.filename, re.I):
                    if entry.file_size > 1024 * 1024:
                        raise ValueError('public_notice_limit')
                    notices.append({'dependency': dependency['name'], 'path': entry.filename, 'sha256': digest(wheel.read(entry))})
    write_new(context / 'requirements.lock', admitted[key(BASE / 'requirements.lock')])
    write_new(context / 'dependencies.v1.json', admitted[key(BASE / 'dependencies.v1.json')])
    write_new(context / 'Dockerfile', admitted[key(ROOT / 'Dockerfile')])
    artifact = artifact_document(commit, dependencies, inputs, transfer, admitted, notices)
    raw = (json.dumps(artifact, ensure_ascii=False, indent=2) + '\n').encode()
    if len(raw) > 1048576:
        raise ValueError('public_artifact_limit')
    write_new(context / 'runtime/public-server-runtime.v1.json', raw)
    write_new(context / 'public-server-runtime.v1.json', raw)
    write_new(context / 'public-server-runtime.v1.json.sha256', (digest(raw) + '\n').encode())
    print(json.dumps({'context': str(context), 'sourceCommit': commit, 'artifactSha256': digest(raw), 'engineImported': False, 'imageBuilt': False, 'published': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', action='store_true')
    args = parser.parse_args()
    if args.prepare:
        prepare()
    else:
        _, _, dependencies, inputs, _, _ = reviewed_source()
        print(json.dumps({'sourceOnly': True, 'ownedFiles': len(inputs), 'pinnedWheels': len(dependencies['dependencies']), 'engineImported': False, 'imageBuilt': False, 'published': False}))
