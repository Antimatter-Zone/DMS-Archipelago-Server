# Fresh bootstrap runtime candidate

This additive image layer closes the startup ordering gap without changing
Wings, Member behavior, the accepted native image, its 22 owned files, native
artifact/profile, or the separate host command package. It is not enrolled for
production. Its normal entrypoint is the new Node PID1 launcher; it starts one
fixed Python worker and no listener. The same worker waits, admits sealed bytes
and invokes the captured native loader.

The Dockerfile requires a protected-build parent reference. Preparation records
the exact expected native full image ID, but explicitly says
`parentImageVerified:false`. A protected image builder must independently bind
that reference to image `sha256:160a05753a026d3d8cfbcafa34d45a9d93f2b658ee0694f41d4f1c9df176ee12`
before building, then verify the inherited native artifact
`7c65cc7984339622d1c515cdc7648af8220c3ade26a076292cc16fbcf3b2411c`, profile
`45d0e5de9dd8aade8197b2e66a36d5b6d1bfcf9e15f713c639c676b6b1978c1e`,
and unchanged 22-file inventory. A declared image label is not that proof.

## Trust and preparation

`runtime/runtime-profile.json` is fixed source input and has no private key.
Default preparation writes unconfigured trust; the entrypoint refuses it before
spawning a worker or creating a challenge. The only runnable trust in this cohort
is explicitly `synthetic-qa-only`. Production is not a selectable fallback.

The public-only QA trust definition is canonical JSON with exactly:

```text
schema: amz.ap.public-beta.bootstrap-trust.v1
mode: synthetic-qa-only
rootPublicKeyPem: an Ed25519 PUBLIC KEY PEM
rootSpkiSha256: SHA-256 of its SPKI DER
```

The builder checks public encoding and an independently supplied expected raw
definition hash. Node's built-in crypto checks actual Ed25519 type and signatures.
No Python cryptographic wheel, hand-written Ed25519, incoming root selector or
private signing key is used. The signing key stays outside the image, runtime,
build context and public APIs. Source tests generate only ephemeral fixture keys.

Explicit Linux context preparation, after committing the producer, is:

```text
<pinned-python> -I -B build.py --prepare --output <new-external-directory>
<pinned-python> -I -B build.py --prepare --output <new-external-directory> --synthetic-public-trust <public-definition> --expected-sha256 <independent-definition-SHA256>
```

The builder uses a captured exact owner-repository Git reader. It captures the
eight regular committed source paths before output, checks the running producer
against its Git blob, and creates a new exclusive context. It performs no image
build/pull/tag, install, package download, network operation or Git mutation.
The generated bootstrap artifact binds actual producer commit, source profile,
four owned bootstrap files and the separate native component. It excludes itself
from its own file inventory, avoiding a self-hash cycle. Source and synthetic QA
metadata assert no issuer/provider enrollment, activation or gameplay.

## Normal entrypoint and private channel

Node retains the native launcher's bounded output draining and signal forwarding.
It verifies the immutable bootstrap source profile/inventory and parent native
artifact/inventory before spawning `/usr/local/bin/python -I -B bootstrap.py`.
Only the fixed image-owned files can provide a trust root. Node/Python versions,
nonroot UID/GID 65532 and the read-only image remain required.

The original 30-second startup ceiling is captured before Node input IO. Node
sends its original dates in the initial `startup-bound` frame; the worker caps
its own budget to those dates. Timers cannot renew that window. Cancellation,
deadline failures and unexpected errors stop the captured child, with bounded
SIGTERM/SIGKILL/close handling. An unknown close is failure, not a fence or release.

Two inherited private pipes are the sole verification channel: FD3 is worker to
parent, FD4 parent to worker. Frames have a four-byte big-endian length followed
by at most 32 KiB of canonical JSON. Their exact keys are `schema`, `direction`,
`sequence`, `kind`, `body`; schema is
`amz.ap.public-beta.bootstrap-channel.v1`. The parent startup frame uses sequence
-1. Worker sequences 0/1/2 are `challenge`, `verify-seal`, `initialized`; replies
are `challenge-accepted`, `seal-verified`, `initialized-accepted`.

Wrong kinds/directions/sequences, malformed UTF-8, BOMs, duplicates, extra data,
partial EOF, oversized frames and late responses refuse. No `approved:true`
record, public endpoint, structural callback or caller-selected source module
can create the worker's private verified-seal/snapshot objects. Mathematical
verification uses Node `crypto.verify` over the exact domain and canonical body.
Native stdout/stderr are drained with a 2-MiB ceiling and never exported or
claimed to be regex-redacted. Bootstrap pipes close before engine import.

## Fresh challenge and fixed files

Only empty fixed `.amz` and `.amz-bootstrap` directories may enter waiting. Missing
directories can be created privately at mode 0700; existing modes/owners are not
repaired. Previous config, seed, keys, scope, lock, journal, save, challenge, seal,
pending file or consumed record refuses a fresh launch. No state is wiped.

The worker generates a random 256-bit nonce and retains it in memory. The fixed
challenge contains nonce, PID1/worker process-start identities, bootstrap artifact
and profile hashes, actual native-root device/inode, and original startup dates.
It proves local process/file observations only. Hostname, cgroup text or challenge
JSON never establish the actual Docker full ID, provider ownership or MFA.

Bootstrap metadata is outside the native kernel's `.amz` inventory. Its separate
64-KiB bound reserves every fixed current/pending maximum plus bounded directory
allocation before writes. Only `challenge.json`, `seal.json`, `consumed.json` and
their one fixed pending name each are recognized. Unknowns are retained and
refused. The unchanged native 3-MiB budget does not cover this sibling; both roots
must be charged by future physical/retained-byte accounting.

The restricted future issuer must prepare exactly these native files:

| File | Maximum |
| --- | --- |
| `public-control-publication.lock` | 2 KiB |
| `public-publication-scope.json` | 16 KiB |
| `public-runtime.json` | 16 KiB |
| `public-seed.archipelago` | 512 KiB |
| `public-yacht-keys.json` | 4 KiB |

All are regular, mode0600, single-link, UID/GID65532 files in the exact private
native root. The host command's three control channels cannot create these five.
The issuer must retain its own durable intent and write/read back files through
a separately reviewed restricted bootstrap operation, then publish the seal last.
No Panel write/chmod, shell, privileged SSH or generic Docker fallback is supplied.

## Seal and native byte binding

The canonical envelope has `schema`, `body`, `signature`; schema is
`amz.ap.public-beta.bootstrap-envelope.v1`. Ed25519 signs
`amz.ap.public-beta.bootstrap-seal.v1`, one newline, then the exact canonical body.
The body has exactly:

```text
schema, sealId, operationId, nonce, challengeSha256, process, identity,
native, bootstrapArtifactSha256, provider, files, issuedAt, expiresAt
```

`process` equals the fresh challenge. `identity` is the existing exact 12-field
native identity. `native` binds parent artifact/profile/source. `provider` has
serverUuid, full containerId, imageId, volumeId and
`attestation:synthetic-qa-only`; these are issuer assertions, not runtime-proven
Docker or operator facts. `files` is the profile's exact sorted five-file list,
each with name, byte count, SHA-256, decimal-string device/inode, UID/GID and mode.
No password, MAC key, signing key or website token belongs in the seal.

Seal admission has a separate maximum-five-second wall/monotonic window captured
before its file read. Node verifies signature/root/nonce/context/dates. Only then
may the worker use the approved scope hash to capture the real publication scope
and lock. It takes a complete five-file held-FD snapshot, checks both FD and named
identities/exact bytes, and rechecks the original challenge/seal descriptors after
IPC. A durable `handoff-intent` is written before consuming admission. That record
is historical intent, not a statement that native code started or saved state.

Admitted bytes remain bound to this worker/nonce/run after seal expiry. Startup
still has the original 30-second ceiling. The captured unchanged parent loader
actually runs its own `verify_inputs` first; the added guard compares its real
seed/key/config/scope buffers with the sealed snapshot. The genuine captured
composition opens its actual NativeFiles owner and lock. An additive instance
wrapper rechecks the held five files and actual lock bytes inside the parent's
existing transaction, calls the original guarded initializer, verifies the real
journal readback and closes snapshots once. Class identities, native RLock,
budget checks and original under-lock input rereads remain intact. No caller
module, subclass, `sys.modules` replacement or native fallback is accepted.

The initialized private notification occurs after that transaction exits. No
publication flock spans channel IO, engine callbacks or awaits. Closing failures
or late/unknown handoff use the genuine composition's retained uncertainty rules.
The permanent byte binding is not a website grant, physical permit, replacement
fence or transferable authorization for a new process. Existing scope, control
and slot-grant clocks continue independently.

## Required actual qualification

Source tests exercise actual Node signatures/framing, inherited Linux pipes,
original budgets, private-brand refusal and real owned FD/publication failures.
Counted isolated UID substitutions in filesystem fixtures cannot create a
production role or native-image proof. The normal image qualification remains a
separate protected operation after source CI.

That operation must start the new image through its own entrypoint with five
files initially absent, observe one stable real full Docker ID while it waits,
use an explicitly synthetic issuer to bind the actual challenge and five-file
readback, then demonstrate genuine native initialization and read-only MAC ACKs.
It must reject changed files, wrong roots/signatures, stale nonces, process replay,
delayed private replies, duplicate handoff, cancellation and old-workspace restart.
Keys must not appear in logs, argv or environment. Synthetic signatures are not
evidence of real provider, current operator/MFA or issuer enrollment.

Actual parent binding, source/image signatures, restricted issuer principal,
protected initial-key custody, genuine retained-target producer, updated provider
approval, full physical permit, restore/resume, gameplay and production activation
remain closed. This cohort changes no historical policy or existing room version.
