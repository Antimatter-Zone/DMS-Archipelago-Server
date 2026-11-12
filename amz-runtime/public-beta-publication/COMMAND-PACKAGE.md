# Versioned two-source publication command package

This additive package separates the host command from the game image. No existing
runtime, image, profile or command/kernel byte is changed. The package contains
only two executable sources: the corrected `command.py` and its fixed
`publication.py` kernel. It includes no interpreter, engine, dependency wheel,
credential, scope enrollment, native data, service configuration or deployment.

`command-package-profile.v1.json` pins component commit
`230ca06351e410bb300a719672a9ed1d45062015`, both exact Git blob IDs/raw SHA-256
values/sizes, the exact repository MIT license, the fixed invocation contract,
and the bounded archive format. The package producer has a **separate** source
commit. The profile does not contain its own hash or producer commit. The builder
pins the raw profile hash; the output manifest records the actual committed
builder/profile blob hashes and producer commit. There is no self-hash cycle.

The builder resolves every fixed source/license path in the actual current
committed producer tree to a regular-file entry with the reviewed component blob
ID, then reads that exact
blob ID and verifies its raw SHA-256 and size. The original component230/path/OID
mapping is independently reviewed and profile-pinned; the builder does not claim
to traverse an unavailable component230 commit in a shallow checkout. Having the
admitted blob as an unrelated dangling object does not suffice: the exact current
producer path must resolve to it. No network fetch or deeper checkout is needed.

The builder reads fixed paths directly from Git objects with replace refs,
optional locks, credential prompts, global/system configuration and inherited
token environment disabled. Lazy fetching is disabled and the Git transport
protocol allowlist is empty. It uses no `show` filters, checkout, Git update,
mutation, working-tree component fallback, sibling repository or network. Each
blob's type, bound, Git object ID, raw SHA-256 and size are checked. All sources
and metadata are captured before output creation. The current producer must be
committed, and its working bytes must exactly match that committed blob.

The resolved Git executable is captured and hash-checked before/after each
bounded read-only child; stdout/stderr and the whole operation are bounded.
Its initial positive hardlink count is measured and must remain exactly the
same during later same-FD/named checks; vendor hardlinks are not treated as
private data. Ordinary producer/source reads and output remain single-link.
The Git binary hash is recorded in the local receipt, not in archive contents,
so equal component/producer commits generate equal archives across tool hosts.
That measurement is not a trusted toolchain approval. The protected build/release
boundary must independently admit the Git/Python tools and producer source.
No key, signing subscription, certificate or release signature is created here.

The explicit preparation command, on Linux, is:

```text
<admitted-python> -I -B <admitted-package.py> --prepare --output <new-external-directory>/publication-command.v1.tar
```

No operation occurs on import. The output parent must already exist, be outside
this repository and have nonsymlink ancestors. Creation walks directory FDs with
nofollow and opens the sole output exclusively. It writes captured bytes, fsyncs
the file and directory, and verifies the held FD, named identity and exact full
readback before printing a receipt. Named parent and ancestor lstat identities
are retained across source/tool IO and rechecked before creation and the final
receipt; replacing an admitted directory with a symlink back to the held FD
refuses even when its dev/inode would match after following the link. The output
leaf's held-FD and named identity are also rechecked after final Git IO and before
receipt, so a later named-file replacement cannot receive the old bytes' hash.
Existing outputs are never overwritten.
Errors retain any partial output for explicit inspection and return nonzero
without printing Git errors, raw source or private paths. There is no automatic
cleanup, installation, extraction, signing, publication or remote operation.

The uncompressed USTAR archive is at most 256 KiB. Its exact ordered regular
entries are:

1. `publication-command/command.py`
2. `publication-command/publication.py`
3. `publication-command/artifact.json`
4. `publication-command/NOTICE.txt`
5. `publication-command/LICENSE`

Every header has mode 0444, UID/GID/mtime zero, empty owner/group/link names, and
no links, devices or PAX metadata. Source and license bytes are unchanged Git
blobs; notices are fixed bounded text. The canonical manifest binds all contents
except itself, component provenance, separate producer provenance and invocation.
The whole archive SHA-256 in an independently protected release manifest must
bind the manifest too. A declared hash alone is not authentication.

The artifact and local receipt explicitly report unsigned, uninstalled,
source-only, activation false and qualification false. Neither constitutes a
current runtime target, slot grant, provider inventory, physical permit or
resource-release proof. Portal must eventually consume this versioned artifact
through independently pinned protected release/configuration bytes, not import
a sibling checkout. A future installed loader must verify the complete fixed
entry inventory, bounds, provenance, hashes and admitted tools before executing
either file. No such loader, issuer or transport is enabled by this source.

Tests read the actual immutable component Git blobs, verify deterministic archive
bytes/headers/license/provenance and reject changed or added sources. Encoder
tests label their producer section synthetic; they do not assert a committed
package-producer or release approval. A real minimal owned shallow Git fixture
has a valid producer commit whose component230 parent object is absent; actual
Git and the unchanged package code must still resolve the admitted current tree.
A variant with the admitted blob merely dangling while the current source path
points elsewhere refuses, even when its working file has the admitted bytes.
The fixture writes only its own temporary Git object files and performs no clone,
fetch or source-repository mutation. One Linux case runs the real committed
producer CLI, verifies full artifact bytes, refuses overwrite and reproduces the
same hash in a new owned directory. That case is explicitly excluded on Windows
and before the new producer/profile are committed at the exact local component230
baseline. CI or any other producer commit treats missing/malformed producer
provenance as a failure, never a skip. Protected Linux source CI must run it after
commit. The case also swaps its real output parent for a symlink during final
Git IO and requires refusal while retaining the exact owned archive. A second
output swap replaces the named archive while retaining the old file and
requires refusal without deleting either file. A separate real owned hardlink
case checks measured tool-count stability while ordinary source reads stay
single-link. These temporary artifacts are test evidence, not published
or installed software. Actual artifact production, signing, distribution,
installation, restricted command principal, target enrollment and real native
delivery remain separate gates.
