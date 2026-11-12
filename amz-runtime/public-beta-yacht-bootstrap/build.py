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
PROFILE_SHA = '0ca69a82df3b31c931ec61d4d8116456e5bf43b672c1b41318557b74c0fcb405'
HELPER_SHA = '1108d887d8c8bc0bf08bb7a1ade32e4a7765268a6045c89b0cfb62a0bf2c9242'
PREFIX = 'amz-runtime/public-beta-yacht-bootstrap/'
SOURCE_FILES = ('build.py', 'Dockerfile', 'runtime/runtime-profile.json', 'runtime/launcher.mjs', 'runtime/bootstrap.py', 'README.md')
TEST_FILES = ('amz-runtime/public-beta/tests/test_yacht_bootstrap_runtime.py',
              'amz-runtime/public-beta/tests/yacht-bootstrap-launcher.test.mjs')


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
    need(path in tuple(PREFIX + name for name in SOURCE_FILES) + TEST_FILES)
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
    need(type(raw) is bytes and 0 < len(raw) <= 2048 and type(expected) is str and
         re.fullmatch('[a-f0-9]{64}', expected) and sha(raw) == expected)
    value = json.loads(raw)
    need(canonical(value) == raw and set(value) == {'schema', 'mode', 'rootPublicKeyPem', 'rootSpkiSha256'} and
         value['schema'] == 'amz.ap.public-beta.bootstrap-trust.v1' and value['mode'] == 'synthetic-qa-only' and
         type(value['rootPublicKeyPem']) is str and len(value['rootPublicKeyPem']) <= 512 and
         re.fullmatch('-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n?', value['rootPublicKeyPem']) and
         type(value['rootSpkiSha256']) is str and re.fullmatch('[a-f0-9]{64}', value['rootSpkiSha256']))
    # This validates public-only encoding/hash, NOT Ed25519 mathematics. Actual
    # type/signature verification is exclusively pinned Node crypto at runtime.
    encoded = value['rootPublicKeyPem'].split('-----BEGIN PUBLIC KEY-----\n')[1].split('-----END PUBLIC KEY-----')[0].replace('\n', '')
    der = base64.b64decode(encoded, validate=True)
    need(base64.b64encode(der).decode() == encoded and sha(der) == value['rootSpkiSha256'])
    return raw


def artifact(commit, profile, files):
    need(re.fullmatch('[a-f0-9]{40}', commit) and set(files) ==
         {'bootstrap.py', 'launcher.mjs', 'runtime-profile.json', 'trust-profile.json'})
    return canonical({'schema': 'amz.ap.public-beta.yacht-bootstrap-artifact.v1', 'version': 1,
        'producerCommit': commit, 'profileSha256': PROFILE_SHA, 'native': profile['native'],
        'ownedFiles': [{'path': name, 'sha256': sha(raw), 'bytes': len(raw)} for name, raw in sorted(files.items())],
        'qualification': profile['qualification']})


def prepare(output, public_file=None, expected_public_sha=None):
    need(sys.platform == 'linux' and os.name == 'posix')
    admitted = helper(); git = admitted._Git(); commit = git.head()
    source = {name: source_blob(git, commit, PREFIX + name) for name in SOURCE_FILES}
    for path in TEST_FILES: source_blob(git, commit, path)
    need(admitted._regular(Path(__file__).absolute(), 262144) == source['build.py'] and
         sha(source['runtime/runtime-profile.json']) == PROFILE_SHA)
    profile = json.loads(source['runtime/runtime-profile.json'])
    if public_file is None:
        need(expected_public_sha is None)
        trust = canonical({'schema': 'amz.ap.public-beta.bootstrap-trust.v1', 'mode': 'unconfigured',
                           'rootPublicKeyPem': None, 'rootSpkiSha256': None})
    else:
        need(type(public_file) is type(ROOT))
        trust = public_trust(admitted._regular(public_file, 2048), expected_public_sha)
    files = {'bootstrap.py': source['runtime/bootstrap.py'], 'launcher.mjs': source['runtime/launcher.mjs'],
             'runtime-profile.json': source['runtime/runtime-profile.json'], 'trust-profile.json': trust}
    raw_artifact = artifact(commit, profile, files)
    need(len(raw_artifact) <= 32768 and git.head() == commit)
    need(type(output) is type(ROOT) and output.is_absolute() and output.parent.resolve() == output.parent and
         not output.is_relative_to(REPOSITORY))
    ancestry = admitted._named_ancestry(output.parent); parent = admitted._directory(output.parent)
    directory_fd = bootstrap_fd = None
    try:
        admitted._named_current(ancestry); need(git.head() == commit)
        os.mkdir(output.name, 0o700, dir_fd=parent); os.fsync(parent)
        directory_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        os.mkdir('bootstrap', 0o755, dir_fd=directory_fd)
        bootstrap_fd = os.open('bootstrap', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
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
        os.fsync(bootstrap_fd); os.fsync(directory_fd); os.fsync(parent)
        need(git.head() == commit); admitted._named_current(ancestry)
        need((output.lstat().st_dev, output.lstat().st_ino) ==
             (os.fstat(directory_fd).st_dev, os.fstat(directory_fd).st_ino) and not output.is_symlink())
    finally:
        for fd in (bootstrap_fd, directory_fd, parent):
            if fd is not None: os.close(fd)
    return {'schema': 'amz.ap.public-beta.bootstrap-context-receipt.v1', 'producerCommit': commit,
            'artifactSha256': sha(raw_artifact), 'profileSha256': PROFILE_SHA,
            'parentImageId': profile['native']['imageId'], 'parentImageVerified': False,
            'trustMode': json.loads(trust)['mode'], 'sourceOnly': True, 'imageBuilt': False,
            'privateKeyIncluded': False, 'issuerEnrolled': False, 'providerEnrolled': False,
            'productionRegistered': False, 'activation': False}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        need(len(argv) in (3, 7) and argv[:2] == ['--prepare', '--output'])
        public_file = expected = None
        if len(argv) == 7:
            need(argv[3] == '--synthetic-public-trust' and argv[5] == '--expected-sha256')
            public_file, expected = Path(argv[4]), argv[6]
        print(canonical(prepare(Path(argv[2]), public_file, expected)).decode())
        return 0
    except BaseException: return 1


if __name__ == '__main__': raise SystemExit(main())
