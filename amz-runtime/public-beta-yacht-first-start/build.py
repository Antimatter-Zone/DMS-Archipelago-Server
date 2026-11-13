"""Prepare a new bootstrap-only layer; never builds, pulls, signs or installs.

The protected image builder must bind its required parent reference to the
profile's exact admitted native image ID. Default trust refuses startup.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import types

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[1]
PROFILE_SHA = 'ce3658a8c96fb7b5e29506d8faf728edd8e962982e5cbad535e18add7365e02d'
HELPER_SHA = '1108d887d8c8bc0bf08bb7a1ade32e4a7765268a6045c89b0cfb62a0bf2c9242'
PREFIX = 'amz-runtime/public-beta-yacht-first-start/'
SOURCE_FILES = ('build.py', 'Dockerfile', 'runtime/runtime-profile.json', 'runtime/launcher.mjs', 'runtime/bootstrap.py',
                'runtime/first_start.py', 'runtime/native_loader.py', 'issuer/publisher.py', 'README.md')
TEST_FILES = ('amz-runtime/public-beta/tests/test_yacht_first_start.py',
              'amz-runtime/public-beta/tests/yacht-first-start.test.mjs')
FOUNDATION_COMMIT = '825e88b9c47c9632fd8179d922498bffcea780cd'
FOUNDATION = {
    'build.py': 'e6a35983c077cf0bf208b2fc4da04446e0511e8f4a1d9abc9d30289b546a3287',
    'Dockerfile': '6b92b51707676775cba93bb45e037dd6bfee63790ac324dd026d1a8f436ef346',
    'README.md': '6ec11562a8fbecbb0b7fb484ecda8ef9fdf7cbd9041191fd78ff7bba1434ab38',
    'issuer/publisher.py': '72ce2c025e35ebde70f5d70c82ba5015e428b64bea7f227e0da62813bb8ccf63',
    'runtime/bootstrap.py': '194beaeb0d0264d5d5780ef85424a68eef2d9c19c55b543d073321dd2fa388d4',
    'runtime/launcher.mjs': '8eab0f2f1e24810954eddd46f1b70569d51bc6e22ae5390362693d1cc62dd14c',
    'runtime/runtime-profile.json': '646ed63b88192e51106b619b1a7a174eb4d29f2d6f55fdd8ea14622cede7422c'}
FOUNDATION_PREFIX = 'amz-runtime/public-beta-yacht-production-bootstrap/'


def need(value):
    if not value: raise ValueError('bootstrap_build_refused')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def helper():
    path = REPOSITORY / 'amz-runtime/public-beta-publication/package.py'
    # Fixed sibling inside this owner repository, captured before execution.
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    try:
        info = os.fstat(fd); need(0 < info.st_size <= 65536 and info.st_nlink == 1)
        raw = bytearray()
        while len(raw) <= 65536:
            part = os.read(fd, min(65536, 65537 - len(raw)))
            if not part: break
            raw.extend(part)
        need(len(raw) == info.st_size and sha(raw) == HELPER_SHA)
        raw = bytes(raw)
    finally: os.close(fd)
    module = types.ModuleType('captured_bootstrap_git_reader'); module.__file__ = str(path)
    exec(compile(raw, '<verified:' + HELPER_SHA + '>', 'exec'), module.__dict__)
    need(module._regular(path, 65536) == raw)
    return module


def source_blob(git, commit, path):
    need(path in tuple(PREFIX + name for name in SOURCE_FILES) + TEST_FILES +
         tuple(FOUNDATION_PREFIX + name for name in FOUNDATION))
    entry = git.run(['ls-tree', '-z', commit, '--', path], 256)
    need(re.fullmatch(b'100644 blob [a-f0-9]{40}\t' + re.escape(path.encode()) + b'\0', entry))
    oid = entry[12:52].decode()
    need(git.run(['cat-file', '-t', oid], 5) == b'blob\n')
    size = git.run(['cat-file', '-s', oid], 16)
    need(re.fullmatch(b'[1-9][0-9]{0,8}\n', size) and int(size) <= 262144)
    raw = git.run(['cat-file', 'blob', oid], 262144)
    need(len(raw) == int(size) and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == oid)
    return raw


def public_trust(raw, expected):
    need(type(raw) is bytes and 0 < len(raw) <= 4096 and type(expected) is str and
         re.fullmatch('[a-f0-9]{64}', expected) and sha(raw) == expected)
    value = json.loads(raw)
    need(canonical(value) == raw and set(value) == {'schema', 'issuer', 'provider', 'launchCommand'} and
         value['schema'] == 'amz.ap.public-beta.yacht-first-start-trust.v1')
    # This validates public-only encoding/hash, NOT Ed25519 mathematics. Actual
    # type/signature verification is exclusively pinned Node crypto at runtime.
    for role, purpose in (('issuer', 'amz.ap.public-beta.production-bootstrap-seal.v1'),
                          ('provider', 'amz.ap.public-beta.yacht-provider-launch.v1'),
                          ('launchCommand', 'amz.ap.public-beta.yacht-first-start-activation.v1')):
        entry = value[role]
        if role == 'launchCommand' and entry is None: continue
        need(type(entry) is dict and set(entry) == {'keyId', 'rootPublicKeyPem', 'rootSpkiSha256'} and entry['keyId'] == purpose and
             type(entry['rootPublicKeyPem']) is str and len(entry['rootPublicKeyPem']) <= 512 and
             re.fullmatch('-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n?', entry['rootPublicKeyPem']) and
             type(entry['rootSpkiSha256']) is str and re.fullmatch('[a-f0-9]{64}', entry['rootSpkiSha256']))
        encoded = entry['rootPublicKeyPem'].split('-----BEGIN PUBLIC KEY-----\n')[1].split('-----END PUBLIC KEY-----')[0].replace('\n', '')
        der = base64.b64decode(encoded, validate=True)
        need(base64.b64encode(der).decode() == encoded and sha(der) == entry['rootSpkiSha256'])
    need(value['issuer']['rootSpkiSha256'] != value['provider']['rootSpkiSha256'])
    need(value['launchCommand'] is None or value['launchCommand']['rootSpkiSha256'] not in
         (value['issuer']['rootSpkiSha256'], value['provider']['rootSpkiSha256']))
    return raw


def artifact(commit, profile, files):
    need(re.fullmatch('[a-f0-9]{40}', commit) and set(files) ==
         {'bootstrap.py', 'first_start.py', 'launcher.mjs', 'native_loader.py', 'runtime-profile.json', 'trust-profile.json'})
    return canonical({'schema': 'amz.ap.public-beta.yacht-first-start-artifact.v1', 'version': 1,
        'producerCommit': commit, 'profileSha256': PROFILE_SHA, 'native': profile['native'],
        'ownedFiles': [{'path': name, 'sha256': sha(raw), 'bytes': len(raw)} for name, raw in sorted(files.items())],
        'qualification': profile['qualification']})


def prepare(output, public_file=None, expected_public_sha=None):
    need(sys.platform == 'linux' and os.name == 'posix')
    admitted = helper(); git = admitted._Git(); commit = git.head()
    for name, digest in FOUNDATION.items():
        path = FOUNDATION_PREFIX + name
        need(sha(source_blob(git, FOUNDATION_COMMIT, path)) == digest and sha(source_blob(git, commit, path)) == digest)
    source = {name: source_blob(git, commit, PREFIX + name) for name in SOURCE_FILES}
    for path in TEST_FILES: source_blob(git, commit, path)
    need(admitted._regular(Path(__file__).absolute(), 262144) == source['build.py'] and
         sha(source['runtime/runtime-profile.json']) == PROFILE_SHA)
    profile = json.loads(source['runtime/runtime-profile.json'])
    need(profile['bootstrap']['workspaceBytes'] == 81920 and profile['firstStart']['consumerImplemented'] is False and
         profile['firstStart']['activationTrustDefault'] is None and profile['firstStart']['imageDigest'] is None)
    if public_file is None:
        need(expected_public_sha is None)
        trust = canonical({'schema': 'amz.ap.public-beta.yacht-first-start-trust.v1', 'issuer': None, 'provider': None, 'launchCommand': None})
    else:
        need(type(public_file) is type(ROOT))
        trust = public_trust(admitted._regular(public_file, 4096), expected_public_sha)
    files = {'bootstrap.py': source['runtime/bootstrap.py'], 'launcher.mjs': source['runtime/launcher.mjs'],
             'first_start.py': source['runtime/first_start.py'], 'native_loader.py': source['runtime/native_loader.py'],
             'runtime-profile.json': source['runtime/runtime-profile.json'], 'trust-profile.json': trust}
    raw_artifact = artifact(commit, profile, files)
    issuer_artifact = canonical({'schema': 'amz.ap.public-beta.yacht-first-start-issuer-artifact.v1',
        'producerCommit': commit, 'profileSha256': PROFILE_SHA,
        'entry': '/opt/dms/public-provider-owner/server/first-start-v1/publisher.py', 'bootstrapWorkspaceBytes': 81920,
        'publisher': {'path': 'publisher.py', 'bytes': len(source['issuer/publisher.py']), 'sha256': sha(source['issuer/publisher.py'])},
        'native': profile['native'], 'qualification': profile['qualification']})
    need(len(raw_artifact) <= 32768 and git.head() == commit)
    need(type(output) is type(ROOT) and output.is_absolute() and output.parent.resolve() == output.parent and
         not output.is_relative_to(REPOSITORY))
    ancestry = admitted._named_ancestry(output.parent); parent = admitted._directory(output.parent)
    directory_fd = bootstrap_fd = issuer_fd = None
    try:
        admitted._named_current(ancestry); need(git.head() == commit)
        os.mkdir(output.name, 0o700, dir_fd=parent); os.fsync(parent)
        directory_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        os.mkdir('bootstrap', 0o755, dir_fd=directory_fd)
        bootstrap_fd = os.open('bootstrap', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
        os.mkdir('issuer', 0o755, dir_fd=directory_fd)
        issuer_fd = os.open('issuer', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
        def write(fd, name, raw):
            need(0 < len(raw) <= 262144)
            handle = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=fd)
            try:
                rest = memoryview(raw)
                while rest:
                    count = os.write(handle, rest); need(count > 0); rest = rest[count:]
                os.fsync(handle)
                before = os.fstat(handle); os.lseek(handle, 0, os.SEEK_SET)
                need(os.read(handle, len(raw) + 1) == raw and before.st_nlink == 1 and
                     admitted._identity(before) == admitted._identity(os.fstat(handle)) ==
                     admitted._identity(os.stat(name, dir_fd=fd, follow_symlinks=False)))
            finally: os.close(handle)
        write(directory_fd, 'Dockerfile', source['Dockerfile'])
        for name, raw in files.items(): write(bootstrap_fd, name, raw)
        write(bootstrap_fd, 'bootstrap-artifact.json', raw_artifact)
        write(issuer_fd, 'publisher.py', source['issuer/publisher.py'])
        write(issuer_fd, 'issuer-artifact.json', issuer_artifact)
        os.fsync(issuer_fd); os.fsync(bootstrap_fd); os.fsync(directory_fd); os.fsync(parent)
        need(git.head() == commit); admitted._named_current(ancestry)
        need((output.lstat().st_dev, output.lstat().st_ino) ==
             (os.fstat(directory_fd).st_dev, os.fstat(directory_fd).st_ino) and not output.is_symlink())
    finally:
        first = None
        for fd in (issuer_fd, bootstrap_fd, directory_fd, parent):
            if fd is not None:
                try: os.close(fd)
                except OSError as error:
                    if first is None: first = error
        if first is not None: raise first
    return {'schema': 'amz.ap.public-beta.yacht-first-start-context-receipt.v1', 'producerCommit': commit,
            'artifactSha256': sha(raw_artifact), 'profileSha256': PROFILE_SHA,
            'parentImageId': profile['native']['imageId'], 'parentImageVerified': False,
            'issuerArtifactSha256': sha(issuer_artifact), 'trustConfigured': public_file is not None, 'sourceOnly': True, 'imageBuilt': False,
            'privateKeyIncluded': False, 'issuerEnrolled': False, 'providerEnrolled': False,
            'productionRegistered': False, 'activation': False}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        need(len(argv) in (3, 7) and argv[:2] == ['--prepare', '--output'])
        public_file = expected = None
        if len(argv) == 7:
            need(argv[3] == '--public-trust' and argv[5] == '--expected-sha256')
            public_file, expected = Path(argv[4]), argv[6]
        print(canonical(prepare(Path(argv[2]), public_file, expected)).decode())
        return 0
    except BaseException: return 1


if __name__ == '__main__': raise SystemExit(main())
