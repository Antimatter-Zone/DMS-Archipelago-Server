"""Deterministic source package tests; no game/image/transport enrollment."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
import zlib

from test_native_publication import load

ROOT = Path(__file__).resolve().parents[2] / 'public-beta-publication'
SOURCE = ROOT / 'package.py'
PROFILE = ROOT / 'command-package-profile.v1.json'
package = load(SOURCE, 'unchanged_publication_command_package_source_fixture')


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = package._profile(PROFILE.read_bytes())
        cls.git = package._Git()
        cls.components = package._component(cls.git, cls.profile, cls.git.head())
        # Only encoder fixtures use this synthetic producer section. No test
        # presents it as a committed builder or accepts it as a release proof.
        cls.producer_fixture = {'commit': package.COMPONENT_COMMIT,
                                'sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                                'profileSha256': package.PROFILE_SHA256,
                                'fixtureOnly': True}

    def shallow_fixture(self, folder, *, wrong_tree=False, link_mode=False):
        """Real minimal Git checkout; only Python writes its OWN temp objects.

        No clone/init/commit/fetch or source-repository Git mutation is needed.
        The parent230 object is deliberately absent; Git sees a shallow commit.
        """
        repository = Path(folder) / 'shallow'; repository.mkdir()
        metadata = repository / '.git'; (metadata / 'objects').mkdir(parents=True)
        (metadata / 'refs/heads').mkdir(parents=True)
        def object_id(kind, raw):
            body = kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw
            oid = hashlib.sha1(body).hexdigest()
            parent = metadata / 'objects' / oid[:2]; parent.mkdir(exist_ok=True)
            path = parent / oid[2:]
            if not path.exists():
                with path.open('xb') as output: output.write(zlib.compress(body))
            return oid
        files = {package.PRODUCER_PATH: SOURCE.read_bytes(), package.PROFILE_PATH: PROFILE.read_bytes(),
                 **self.components}
        nodes = {}
        for name, raw in files.items():
            admitted = object_id('blob', raw)  # Present even if intentionally dangling.
            node = nodes
            parts = name.split('/')
            for part in parts[:-1]: node = node.setdefault(part, {})
            node[parts[-1]] = object_id('blob', b'not the admitted command') if wrong_tree and name.endswith('/command.py') else admitted
            path = repository / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)  # Correct working bytes do not repair a wrong tree.
        def tree(node):
            raw = bytearray()
            for name in sorted(node, key=lambda n: n + ('/' if type(node[n]) is dict else '')):
                child = node[name]; directory = type(child) is dict
                oid = tree(child) if directory else child
                mode = '40000' if directory else ('120000' if link_mode and name == 'command.py' else '100644')
                raw.extend(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid))
            return object_id('tree', bytes(raw))
        commit = ('tree ' + tree(nodes) + '\nparent ' + package.COMPONENT_COMMIT + '\n'
                  'author Source fixture <fixture@example.invalid> 1 +0000\n'
                  'committer Source fixture <fixture@example.invalid> 1 +0000\n\n'
                  'Owned shallow source fixture\n').encode()
        producer = object_id('commit', commit)
        (metadata / 'HEAD').write_text('ref: refs/heads/source\n')
        (metadata / 'refs/heads/source').write_text(producer + '\n')
        (metadata / 'shallow').write_text(producer + '\n')
        (metadata / 'config').write_text('[core]\nrepositoryformatversion = 0\nbare = false\nfilemode = false\n')
        return repository, producer

    def test_actual_exact_git_blobs_are_pinned_and_working_tree_is_not_a_fallback(self):
        self.assertEqual(self.profile['component']['commit'], '230ca06351e410bb300a719672a9ed1d45062015')
        rows = [*self.profile['component']['files'], self.profile['component']['license']]
        for row in rows:
            raw = self.components[row['path']]
            self.assertEqual(len(raw), row['bytes'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row['sha256'])
            self.assertEqual(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), row['gitBlob'])
        self.assertEqual(hashlib.sha256(self.components['LICENSE']).hexdigest(),
                         'f66c14cec56600dec0a63c5dc14d9fe3dc4efbcdfbf34b100b6fcf1f1e3ded00')
        with patch.object(package, '_regular', side_effect=AssertionError('no working component source')):
            # The pure encoder consumes the already captured exact Git bytes.
            self.assertTrue(package._archive(self.profile, self.components, self.producer_fixture))

    def test_profile_is_exact_and_sources_cannot_be_replaced_or_extended(self):
        with self.assertRaises(ValueError): package._profile(PROFILE.read_bytes() + b' ')
        for bad in ({}, {**self.components, 'extra.py': b'code'},
                    {**self.components, self.profile['component']['files'][0]['path']: b'arbitrary source'}):
            with self.assertRaises(ValueError): package._archive(self.profile, bad, self.producer_fixture)
        for bad in ({}, object.__new__(package.CapturedCommandPackage)):
            with self.assertRaises(ValueError): package.package_bytes(bad)
        with self.assertRaises(ValueError): package.CapturedCommandPackage()

    def test_measured_tool_accepts_vendor_hardlinks_but_refuses_count_drift_and_keeps_sources_single_link(self):
        with tempfile.TemporaryDirectory(prefix='amz-package-measured-tool-') as folder:
            path = Path(folder) / 'measured-tool'; path.write_bytes(b'owned test data, never executed')
            os.link(path, Path(folder) / 'vendor-link1'); os.link(path, Path(folder) / 'vendor-link2')
            digest, links = package._measure_tool(path)
            self.assertEqual(links, 3)
            tool = object.__new__(package._Git)
            tool.executable, tool.tool_sha256, tool.tool_links = path, digest, links
            tool.deadline = time.monotonic() + 30
            tool.current()  # Actual held-FD/name/hash check; no child execution.
            with self.assertRaises(ValueError): package._regular(path, 65536)
            os.link(path, Path(folder) / 'new-link')
            with self.assertRaises(ValueError): tool.current()

    def test_real_shallow_checkout_uses_current_committed_tree_not_missing_parent_or_dangling_blob(self):
        for wrong_tree, link_mode in ((False, False), (True, False), (False, True)):
            with self.subTest(wrong_tree=wrong_tree, link_mode=link_mode), tempfile.TemporaryDirectory(prefix='amz-command-shallow-source-') as folder:
                repository, producer = self.shallow_fixture(folder, wrong_tree=wrong_tree, link_mode=link_mode)
                actual = load(repository / package.PRODUCER_PATH, 'owned_shallow_package_fixture_' + str(wrong_tree) + str(link_mode))
                git = actual._Git()
                self.assertEqual(git.run(['rev-parse', '--is-shallow-repository'], 5), b'true\n')
                with self.assertRaises(ValueError): git.run(['cat-file', '-t', package.COMPONENT_COMMIT], 10)
                self.assertEqual(git.environment['GIT_ALLOW_PROTOCOL'], '')
                self.assertEqual(git.environment['GIT_NO_LAZY_FETCH'], '1')
                if wrong_tree or link_mode:
                    with self.assertRaises(ValueError): actual.capture_package_sources()
                else:
                    captured = actual.capture_package_sources()
                    raw = actual.package_bytes(captured)
                    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
                        manifest = json.loads(archive.extractfile('publication-command/artifact.json').read())
                        self.assertEqual(manifest['producer']['commit'], producer)
                        self.assertEqual(manifest['component']['commit'], package.COMPONENT_COMMIT)
                        self.assertEqual(manifest['componentProvenance'], 'reviewed-profile-pins-and-current-producer-tree')

    def test_artifact_is_byte_deterministic_with_fixed_headers_and_only_two_executable_sources(self):
        first = package._archive(self.profile, self.components, self.producer_fixture)
        second = package._archive(self.profile, self.components, self.producer_fixture)
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), package.ARCHIVE_LIMIT)
        with tarfile.open(fileobj=io.BytesIO(first), mode='r:') as archive:
            members = archive.getmembers()
            self.assertEqual([m.name for m in members], self.profile['archive']['entryOrder'])
            self.assertEqual([m.name for m in members if m.name.endswith('.py')],
                             ['publication-command/command.py', 'publication-command/publication.py'])
            for member in members:
                self.assertTrue(member.isfile()); self.assertFalse(member.issym()); self.assertFalse(member.islnk())
                self.assertEqual((member.uid, member.gid, member.mtime, member.mode), (0, 0, 0, 0o444))
                self.assertEqual((member.uname, member.gname, member.linkname, member.pax_headers), ('', '', '', {}))
            for index, row in enumerate(self.profile['component']['files']):
                self.assertEqual(archive.extractfile(members[index]).read(), self.components[row['path']])
            self.assertEqual(archive.extractfile('publication-command/LICENSE').read(), self.components['LICENSE'])

    def test_manifest_separates_component_and_producer_without_self_hash_or_false_authority(self):
        raw = package._archive(self.profile, self.components, self.producer_fixture)
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            encoded = archive.extractfile('publication-command/artifact.json').read()
            manifest = json.loads(encoded)
            self.assertEqual(encoded, package._canonical(manifest))
            self.assertEqual(manifest['component'], self.profile['component'])
            self.assertEqual(manifest['producer'], self.producer_fixture)
            self.assertEqual(manifest['invocation'], self.profile['invocation'])
            self.assertEqual({row['path'] for row in manifest['contents']},
                             set(self.profile['archive']['entryOrder']) - {'publication-command/artifact.json'})
            for row in manifest['contents']:
                data = archive.extractfile(row['path']).read()
                self.assertEqual((len(data), hashlib.sha256(data).hexdigest()), (row['bytes'], row['sha256']))
            for key in ('signed', 'installed', 'activation', 'qualification', 'targetAuthority', 'resourceReleaseAuthorized'):
                self.assertIs(manifest[key], False)
            notice = archive.extractfile('publication-command/NOTICE.txt').read()
            self.assertIn(package.COMPONENT_COMMIT.encode(), notice)
            self.assertNotIn(b'private key', encoded.lower())

    def test_producer_change_changes_package_without_changing_component_tuple(self):
        raw = package._archive(self.profile, self.components, self.producer_fixture)
        changed = package._archive(self.profile, self.components, {**self.producer_fixture, 'commit': 'a' * 40})
        self.assertNotEqual(hashlib.sha256(raw).digest(), hashlib.sha256(changed).digest())
        self.assertEqual(self.profile['component']['commit'], package.COMPONENT_COMMIT)

    def test_cli_refuses_unsupported_modes_before_capture_or_any_output(self):
        with patch.object(package, 'prepare', side_effect=AssertionError('no prepare')):
            for argv in ([], ['--publish'], ['--prepare', '--root', '/srv'], ['--prepare', '--output']):
                self.assertEqual(package.main(argv), 1)
        source = SOURCE.read_text()
        self.assertNotIn('urlopen', source)
        self.assertNotIn('docker', source.lower())
        self.assertNotIn('git push', source)
        self.assertNotIn('git commit', source)

    @unittest.skipUnless(sys.platform == 'linux', 'Real Linux exclusive archive output; no simulated Windows dirfd')
    def test_committed_producer_cli_reads_git_and_exclusively_publishes_only_local_unsigned_archive(self):
        # Pre-commit source development honestly cannot claim this provenance.
        # The protected source CI runs it after these four paths are committed.
        git = package._Git(); head = git.head()
        try:
            git.blob(head, package.PRODUCER_PATH, 65536)
            git.blob(head, package.PROFILE_PATH, 8192)
        except ValueError:
            if os.environ.get('CI') or os.environ.get('GITHUB_ACTIONS') or head != package.COMPONENT_COMMIT:
                self.fail('The committed CI producer/profile must resolve with exact regular Git provenance')
            self.skipTest('Package producer/profile not committed yet; actual source CI must execute after commit')
        with tempfile.TemporaryDirectory(prefix='amz-command-package-source-') as folder:
            output = Path(folder) / package.ARCHIVE_NAME
            result = subprocess.run([sys.executable, '-I', '-B', str(SOURCE), '--prepare', '--output', str(output)],
                                    capture_output=True, timeout=40)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b'')
            receipt = json.loads(result.stdout)
            self.assertEqual(receipt['componentCommit'], package.COMPONENT_COMMIT)
            self.assertEqual(receipt['producerCommit'], head)
            actual = output.read_bytes()
            self.assertEqual((receipt['artifactSha256'], receipt['bytes']), (hashlib.sha256(actual).hexdigest(), len(actual)))
            with tarfile.open(fileobj=io.BytesIO(actual), mode='r:') as archive:
                manifest = json.loads(archive.extractfile('publication-command/artifact.json').read())
                self.assertEqual(manifest['producer']['commit'], head)
                producer, oid = git.blob(head, package.PRODUCER_PATH, 65536)
                self.assertEqual((manifest['producer']['sha256'], manifest['producer']['gitBlob']),
                                 (hashlib.sha256(producer).hexdigest(), oid))
            again = subprocess.run([sys.executable, '-I', '-B', str(SOURCE), '--prepare', '--output', str(output)],
                                   capture_output=True, timeout=40)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual((again.stdout, again.stderr, output.read_bytes()), (b'', b'', actual))
            another = Path(folder) / 'other'; another.mkdir()
            second = package.prepare(another / package.ARCHIVE_NAME)
            self.assertEqual(second['artifactSha256'], receipt['artifactSha256'])
            parent = Path(folder) / 'swap-parent'; parent.mkdir()
            retained = Path(folder) / 'retained-original-parent'
            original_head, calls = package._Git.head, []
            def swapped_head(git):
                result = original_head(git); calls.append(result)
                if len(calls) == 4:  # Real final Git IO after the complete FD write/readback.
                    parent.rename(retained); parent.symlink_to(retained, target_is_directory=True)
                return result
            with patch.object(package._Git, 'head', new=swapped_head):
                with self.assertRaises(ValueError): package.prepare(parent / package.ARCHIVE_NAME)
            self.assertEqual(len(calls), 4)
            self.assertTrue(parent.is_symlink())
            self.assertEqual((retained / package.ARCHIVE_NAME).read_bytes(), actual)
            leaf_parent = Path(folder) / 'leaf-parent'; leaf_parent.mkdir()
            leaf = leaf_parent / package.ARCHIVE_NAME
            retained_leaf = leaf_parent / 'retained-original.tar'
            calls.clear()
            def swapped_leaf_head(git):
                result = original_head(git); calls.append(result)
                if len(calls) == 4:
                    leaf.rename(retained_leaf); leaf.write_bytes(b'foreign named replacement')
                return result
            with patch.object(package._Git, 'head', new=swapped_leaf_head):
                with self.assertRaises(ValueError): package.prepare(leaf)
            self.assertEqual(len(calls), 4)
            self.assertEqual(retained_leaf.read_bytes(), actual)
            self.assertEqual(leaf.read_bytes(), b'foreign named replacement')


if __name__ == '__main__': unittest.main()
