# Server-owned Public runtime candidate

This additive `public-disposable-beta-v1` profile belongs to
`Antimatter-Zone/DMS-Archipelago-Server`, composition
`server-headless-public-slot-gateway-v1`. The future image repository is
`docker.darkmatterservers.com/dms-public-beta/ap-runtime-public-beta`. This is
reviewed naming only: no Harbor project, published image, digest, configuration
image ID, egg or production placement is created or qualified here.

The accepted Member `f76abdbc` overlay, builder, inventory, dependencies and
acceptance record are unchanged. Its APQuest-labeled protocol/checkpoint
acceptance does not qualify this Public profile or Yacht Dice gameplay.

## Ownership and immutable artifact

`source-transfer.v1.json` records raw Git blobs from Portal commit
`29a39c3431a6607b2e9faade355a92f16d6fd74f`. The barrier, hooks, fixed-file owner
and original manifest are byte-exact. Only the two copied fixture import paths
are relocated, with before/after hashes and the original Git blob recorded.
The historical Portal manifest remains unchanged with its open qualification;
it is not silently relabeled as a Server release. No runtime imports Portal or
a sibling checkout. Generic Wrapper lifecycle may launch the fixed Server
entrypoint; it does not own AP authentication, game state or this overlay.

The new external source artifact is `amz.ap.public-beta.server-runtime.v1`:

```text
schema, version:1, repository, sourceCommit, profileId,
composition, imageRepository,
engine {version,commit,archiveSha256,inventorySha256,
        worldPackSha256,headlessHintsSha256},
ownedFiles [{path,sha256,bytes}], toolchain, sourceTransfer, qualification
```

Its exact bytes/hash, owning Server commit, image digest/configuration image ID,
profile/composition, engine/pack and provenance must be independently admitted
by the protected Portal release/operator policy. Portal consumes this artifact;
it never executes source from this checkout. Runtime image SHA is external to
the artifact because embedding the digest of an image containing the artifact
would create a hash cycle. A separate publication/qualification receipt binds
the immutable source artifact to the resulting image.

The new `runtime-profile.json` hash is the Public world-pack/profile identity.
It binds the full existing engine inventory and headless metadata, the new
control protocol and **Yacht Dice only**. It is distinct from Member inventory
`ea87c2f9…d508f54f`. The complete 3,539-entry inventory and original archive bytes
remain checked; no executable world is imported merely to prepare metadata.
New games require a separately reviewed profile/package, not an automatic
metadata or qualification promotion.

## Protected startup contract

The fixed image entrypoint is `node /opt/amz-ap-public/launcher.mjs`. Node checks
its actual version, independently pinned artifact and every owned file before
spawning the fixed isolated Python loader. Python requires Linux/Python3.12,
nonroot container execution, read-only engine/owned sources, owned private0700
storage and regular single-link private0600 inputs. It verifies configuration,
artifact, owned source, complete engine inventory, headless metadata and seed
hash before any engine import. Source loading executes verified owned bytes;
the engine remains on the immutable verified mount. Binary reads preserve raw
CR bytes, and engine digest normalization occurs exactly once.

The protected operator—not an ordinary caller—writes
`/home/container/.amz/public-runtime.json` with exactly:

```text
schema:'amz.ap.public-beta.native-configuration.v1',
profileId:'public-disposable-beta-v1',
identity {appVariant,policyId,environmentId,dataEpoch,roomId,externalId,
          allocationRevision,serverId,attemptId,seedRevision,credentialEpoch,
          runtimeLaunchId},
runtimeArtifactSha256, worldPackSha256, engineCommit, engineInventorySha256,
seedArtifactSha256, password, port,
journalMode:'initialize', requiredCheckpointSha256:null
```

The operator must already have verified its signed release, current CP scope,
exact image/placement and artifact pins. This protected file is not itself a
new signature or permission granted by a browser request. `password` is the
private native master, never a player slot secret or AMZ token. It appears in
neither argv nor inherited environment. Other fixed private files are
`public-seed.archipelago`, `public-seed.apsave`, `public-runtime-status.json`
and the original `public-gateway-{journal,control,ack}.json` channels. No caller
chooses paths, a backend, imports, commands or remote administration.

Journal creation is an **explicit protected initialize command**. Missing state
never selects it implicitly; stale journal/control/ACK/save/status files refuse
fresh startup and remain preserved. This first profile rejects restore,
baseline migration and held-fence reopening. Those are required later source
gates, not fictional fallback implementations. No old launch is rebound and no
new process invents a replacement idle clock.

The loader preserves the exact native Context class. Core settings are fixed
without creating a mutable host file/eager world loader; reviewed hint metadata
replaces only that loader. Hook installation and mandatory master/proof log
redaction precede native acceptance. The protected exact slot/game binding is
checked after seed load. Initial-ready is recorded only after the actual native
WebSocket server reports serving sockets on the exact configured port. Gateway
startup or an allocated object is not readiness. Native status is private,
bounded, atomically replaced and directory-fsynced; unknown is never zero.

The concrete file owner journals/fsyncs consumed private reservations before
native Connect. Slotted native objects are not modified; both wall/monotonic
lifetimes are checked after durable IO. Admission gates remain held and
uncertainty survives timeouts/crashes. The barrier does not authorize provider
stop/deletion, budgets,30/60-minute actions or capacity release. Safe sleep,
restore/reopen/baseline migration and the token-free trusted current-account
adapter remain separate required integration work.

The additive [checkpoint custody source](CHECKPOINT-CUSTODY.md) implements a
fixed-file native-save/barrier envelope and explicit protected journal migration
primitive. It preserves original idle history and a retained admission hold,
including exact post-stop journal binding and safe lost-ACK replay. It is
included in the owned source inventory, but the loader's restore/reopen gates
remain closed until the native serializer, stop authority and current Play
composition are implemented and qualified. No acceptance flag is promoted.
The new [native checkpoint/control source](NATIVE-CHECKPOINT-CONTROL.md) wires
the exact native snapshot hook to serialized atomic local saves, an equivalent
dirty periodic saver and a distinct held terminal-capture channel. Real native
codec/session, operator stop and restore/reopen qualification remain open.

## Source check and later build preparation

Light commands execute no engine, Docker, network or package installation:

```text
python -I -B amz-runtime/public-beta/build.py
python -I -B -m unittest discover -s amz-runtime/public-beta/tests -p test_*.py
node --test amz-runtime/public-beta/tests/launcher.test.mjs
```

The dedicated `public-beta-source-checks.yml` runs only this exact Public
branch, pinned checkout, Node24.20 and Python3.12 on the approved source worker.
It runs these local fixtures without engine import, context preparation,
dependency installation, image build or publication. Its preflight checks the
actual source SHA, repository, branch, worker identity and interpreter versions.
Source-heavy upstream jobs skip only push/PR-head events for this exact Public
branch; all other historical bytes, tags, permissions and manual behavior are
preserved by pinned regression checks. Existing tag publishers and PR labeling
remain unchanged. Controller admission of this new source lane is a separate
reviewed tooling change, not permission granted by this workflow alone.

The copied POSIX native-files fixtures and new status durability case explicitly
exclude unsupported Windows behavior. Windows source success is not Linux
directory-fsync/flock, native engine or power-loss qualification.

Only after source review/commit and the actual shared scheduling lease may an
operator explicitly run `python -I -B amz-runtime/public-beta/build.py --prepare`.
It requires a clean full Git commit and raw input bytes equal to Git blobs,
verifies the accepted source helper/base pins, downloads only the existing
hash-pinned archive/eight wheels into a separate cache, and creates a **new**
ignored `amz-runtime/.build/context-public-beta-<commit>`. Existing/partial
contexts are never overwritten or removed. It preserves engine/dependency
notices and emits the Public artifact/hash. It does not run Docker or publish.
The prepared Dockerfile installs only those wheel hashes with networking off;
runtime performs no download, dependency update or installation.
The complete input snapshot is captured once and those exact bytes are proved
against the selected Git commit. Context copies, helper metadata and recipe
hashes use that snapshot after verification; later path rereads cannot relabel
earlier dirty input as a clean commit or change output during a long fetch.

Build-time qualification fields record source-only claims, not authorization.
Actual image/egg/signature/redistribution approval, native hook/control
acceptance, protected restart/baseline reconciliation, resources, real Yacht
clients/items/checks, encrypted native+browser save/resume, DMS/Wings ingress and
production registration all remain open. The generic existing Member receipts
and the Portal Linux native-files fixture do not close these Public gates.
