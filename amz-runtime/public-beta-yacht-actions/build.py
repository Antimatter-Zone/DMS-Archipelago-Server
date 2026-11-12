"""Source-only by default. Explicit preparation uses pinned cached bytes only.

Never fetches, installs, imports an engine, builds an image or publishes. Actual
preparation requires a clean committed captured source and a NEW external path.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import types
import zipfile

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[1]
FOUNDATION_SHA = '47a0f816595034f8620a2d200b12ce24e77f3b50e117eb3d37572c0282039ad0'
PROFILE_SHA = '7190f98fe01ed797cd43db72a7d205d22f93ef4a11a1536263ac8a886595cc72'
NEW = ('build.py', 'Dockerfile', 'source-foundation.v1.json', 'README.md', 'runtime/loader.py', 'runtime/launcher.mjs',
       'runtime/runtime-profile.json', 'runtime/yacht_packet_policy.py', 'runtime/native_budget.py')


def digest(raw): return hashlib.sha256(raw).hexdigest()


def need(ok):
    if not ok: raise ValueError('yacht_build_refused')


def key(file): return file.relative_to(REPOSITORY).as_posix()


def regular(file, maximum=262144):
    need(file.is_absolute() and file.resolve() == file)
    for p in file.parents:
        info = p.lstat(); need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode))
    info = file.lstat(); need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum)
    fd = os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    try:
        before = os.fstat(fd); raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part: break
            raw.extend(part)
        after, named = os.fstat(fd), file.lstat()
        ident = lambda v: (v.st_dev, v.st_ino, v.st_mode, v.st_nlink, v.st_size, v.st_mtime_ns,
                           v.st_birthtime_ns if sys.platform == 'win32' else v.st_ctime_ns)
        need(ident(info) == ident(before) == ident(after) == ident(named) and len(raw) == info.st_size)
        return bytes(raw)
    finally: os.close(fd)


def reviewed_source():
    raw = regular(ROOT / 'source-foundation.v1.json'); need(digest(raw) == FOUNDATION_SHA)
    provenance = json.loads(raw); admitted = {}
    for row in provenance['files']:
        data = regular(REPOSITORY / row['path'], 2097152)
        need(len(data) == row['bytes'] and digest(data) == row['sha256'] and
             hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == row['gitBlob'])
        admitted[row['path']] = data
    for name in NEW: admitted[key(ROOT / name)] = regular(ROOT / name)
    test_path = REPOSITORY / 'amz-runtime/public-beta/tests/test_yacht_action_runtime.py'
    admitted[key(test_path)] = regular(test_path)
    fresh = types.ModuleType('captured_fresh_source_builder')
    fresh.__file__ = str(REPOSITORY / 'amz-runtime/public-beta/build.py')
    exec(compile(admitted['amz-runtime/public-beta/build.py'], fresh.__file__, 'exec'), fresh.__dict__)
    # The historical helper reads ONLY our captured map, never a later path.
    fresh.regular = lambda file, maximum=262144: admitted[key(file)]
    base, manifest, dependencies, inputs, transfer, _ = fresh.reviewed_source()
    inputs = dict(inputs); inputs['fresh_loader.py'] = inputs['loader.py']; inputs['fresh-runtime-profile.json'] = inputs['runtime-profile.json']
    for name in ('loader.py', 'launcher.mjs', 'runtime-profile.json', 'yacht_packet_policy.py', 'native_budget.py'):
        inputs[name] = admitted[key(ROOT / 'runtime' / name)]
    for origin, target in (('public-beta-effects/runtime/native_yacht_effects.py', 'native_yacht_effects.py'),
                           ('public-beta-effects/runtime/profile.v1.json', 'effects-profile.v1.json'),
                           ('public-beta-observations/runtime/native_yacht_observations.py', 'native_yacht_observations.py'),
                           ('public-beta-observations/runtime/profile.v1.json', 'observation-profile.v1.json')):
        inputs[target] = admitted['amz-runtime/' + origin]
    inputs['source-foundation.v1.json'] = raw
    need(digest(inputs['runtime-profile.json']) == PROFILE_SHA)
    profile = json.loads(inputs['runtime-profile.json'])
    need(digest(inputs['native_budget.py']) == profile['nativeBudget']['sourceSha256'] and digest(inputs['yacht_packet_policy.py']) == profile['packetPolicy']['sha256'] and
         digest(inputs['native_yacht_effects.py']) == profile['modules']['effectsSha256'] and
         digest(inputs['native_yacht_observations.py']) == profile['modules']['observationSha256'])
    return fresh, base, manifest, dependencies, types.MappingProxyType(inputs), transfer, types.MappingProxyType(admitted), provenance


def git_commit(admitted):
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
    env.update(GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL='', GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
    def git(*args, absent=False):
        r = subprocess.run(['git', '-c', 'core.fsmonitor=false', *args], cwd=REPOSITORY, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        need(len(r.stdout) <= 2097152 and len(r.stderr) <= 65536)
        need(r.returncode == 0 or absent and r.returncode == 1 and not r.stdout and not r.stderr)
        return r.stdout
    common = git('config', '--local', '--no-includes', '--null', '--list')
    def audit(raw):
        entries = []
        for item in raw.split(b'\0'):
            if not item: continue
            k, sep, value = item.partition(b'\n'); need(sep)
            name = k.decode().lower(); need(not(name.startswith('include.') or name.startswith('includeif.') or 'promisor' in name or 'partialclone' in name))
            entries.append((name, value))
        return entries
    entries = audit(common); flags = [v for k, v in entries if k == 'extensions.worktreeconfig']
    need(len(flags) <= 1 and (not flags or flags[0] in (b'true', b'false')))
    if flags == [b'true']: audit(git('config', '--worktree', '--no-includes', '--null', '--list'))
    commit = git('rev-parse', 'HEAD^{commit}').decode().strip(); need(re.fullmatch('[a-f0-9]{40}', commit))
    need(not git('status', '--porcelain', '--untracked-files=all').strip())
    for name, raw in admitted.items():
        row = git('ls-tree', commit, '--', name).decode().split(); need(row[:2] == ['100644', 'blob'])
        need(git('cat-file', 'blob', commit + ':' + name) == raw)
    return commit


def notices(raw):
    result = []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        rows = archive.infolist(); need(len(rows) <= 10000 and len({r.filename for r in rows}) == len(rows))
        need(sum(r.file_size for r in rows) <= 134217728)
        for row in rows:
            need(not row.flag_bits & 1 and not stat.S_ISLNK(row.external_attr >> 16) and
                 not row.filename.startswith(('/', '\\')) and '\\' not in row.filename and
                 all(part not in ('.', '..') for part in row.filename.rstrip('/').split('/')))
            if re.search(r'(?:^|/)(?:LICENSE[^/]*|COPYING[^/]*|NOTICE[^/]*)$', row.filename, re.I):
                need(0 < row.file_size <= 1048576); content = archive.read(row)
                result.append({'path': row.filename, 'bytes': len(content), 'sha256': digest(content)})
    need(result); return result


def artifact_document(commit, source, notices_inventory=()):
    fresh, base, manifest, dependencies, inputs, transfer, admitted, provenance = source
    need(re.fullmatch('[a-f0-9]{40}', commit))
    value = fresh.artifact_document(commit, dependencies, inputs, transfer, admitted, notices_inventory)
    value.update(schema='amz.ap.public-beta.yacht-action-runtime.v1', profileId='public-yacht-actions-fresh-v1',
                 composition='server-headless-public-yacht-actions-v1', executionProfileSha256=PROFILE_SHA, sourceFoundation=provenance)
    value['ownedFiles'] = [{'path': name, 'sha256': digest(raw), 'bytes': len(raw)} for name, raw in sorted(inputs.items())]
    value['toolchain'].update(builderSha256=digest(admitted[key(ROOT / 'build.py')]), dockerfileSha256=digest(admitted[key(ROOT / 'Dockerfile')]))
    return value


def prepare(cache, output):
    source = reviewed_source(); fresh, base, manifest, dependencies, inputs, transfer, admitted, provenance = source
    commit = git_commit(admitted)
    cache, output = cache.absolute(), output.absolute()
    need(cache.resolve() == cache and output.parent.resolve() == output.parent and not output.exists() and not output.is_symlink() and
         not output.is_relative_to(REPOSITORY) and not output.is_relative_to(cache) and not cache.is_relative_to(output))
    for p in (cache, *cache.parents, output.parent, *output.parent.parents):
        info = p.lstat(); need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode))
    archive = regular(cache / base.ENGINE_ARCHIVE_SHA256, 33554432); need(digest(archive) == base.ENGINE_ARCHIVE_SHA256)
    wheels, notice_rows = [], []
    for dependency in dependencies['dependencies']:
        raw = regular(cache / dependency['sha256'], 16777216); need(digest(raw) == dependency['sha256'])
        name = dependency['url'].rsplit('/', 1)[-1]; need(re.fullmatch(r'[A-Za-z0-9_.+-]+\.whl', name))
        rows = notices(raw); notice_rows.extend(dict(row, dependency=dependency['name']) for row in rows); wheels.append((name, raw))
    # Revalidate captured source provenance after all cache IO, before creation.
    need(git_commit(admitted) == commit)
    output.mkdir(); engine = output / 'engine'; engine.mkdir()
    base.extract_inventory(archive, manifest, engine); base.verify_hints(engine)
    def write(name, raw):
        target = output / name; target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as fd: fd.write(raw)
    for name, raw in inputs.items(): write('runtime/' + name, raw)
    for name in ('engine-manifest.json', 'world-hints.v1.json'): write('runtime/' + name, admitted['amz-runtime/' + name])
    for name in ('requirements.lock', 'dependencies.v1.json'): write(name, admitted['amz-runtime/' + name])
    for name, raw in wheels: write('wheels/' + name, raw)
    write('Dockerfile', admitted[key(ROOT / 'Dockerfile')])
    artifact = (json.dumps(artifact_document(commit, source, notice_rows), ensure_ascii=False, indent=2) + '\n').encode(); need(len(artifact) <= 1048576)
    write('runtime/public-yacht-runtime.v1.json', artifact); write('public-yacht-runtime.v1.json', artifact)
    print(json.dumps({'context': str(output), 'sourceCommit': commit, 'artifactSha256': digest(artifact), 'sourceOnly': True, 'imageBuilt': False, 'engineImported': False, 'published': False}))


if __name__ == '__main__':
    import sys
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--prepare', action='store_true'); parser.add_argument('--cache', type=Path); parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.prepare:
        need(args.cache is not None and args.output is not None); prepare(args.cache, args.output)
    else:
        need(args.cache is None and args.output is None); source = reviewed_source()
        print(json.dumps({'sourceOnly': True, 'ownedFiles': len(source[4]), 'pinnedWheels': len(source[3]['dependencies']), 'engineImported': False, 'imageBuilt': False, 'published': False}))
