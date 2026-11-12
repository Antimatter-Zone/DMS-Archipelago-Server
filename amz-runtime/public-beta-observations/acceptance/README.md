# Genuine native Context component acceptance

`qualify_native_context.py` is an explicit private acceptance entrypoint, not a
runtime loader or public workflow. It fails unless actual prerequisites exist;
there is no synthetic Context, missing-engine fallback, listener or game client.
Existing candidate modules/profiles and their qualification flags are unchanged.

## Supervisor prerequisites

The private supervisor must independently verify and bind:

- Exact existing fresh79 local image ID
  `sha256:1b9104acd36cb98950aee35e08c12a70ea3efa78b6a55b90ebaaa1d76ce6fc03`,
  source79e2b0d293d9d6f1f12ee05d6bfe8cb13fd6392e. This is a local daemon image
  identity, not a registry publication or image-configuration-digest claim.
- Actual reviewed source bytes for this acceptance helper and candidate commit
  `7a9a047afd6c38e9bcce4b98053ee43296f9386b`. New helper commits bind their own
  captured hash separately; no self-referential source-commit field is invented.
- A previously genuinely generated two-player Yacht seed, exact bytes/hash and
  generation provenance. The known previous seed is9864bytes, SHA256
  `fe2871d905d6f9f4261f55823c74d6867f238af4f64f3e3bdfa0d51b5f8d4d5f`.
  Independently verify the file and receipt; a matching filename is insufficient.
- The actual shared scheduling lease; persisted operation/container identities
  before create; final full-ID ownership, process exit and positive cleanup.
- Network `none`, no published ports, root filesystem read-only, uid65532:65532,
  bounded writable disposable tmpfs only, capabilities dropped, no-new-privileges,
  reviewed CPU/RAM/pids limits, and no host workspace/profile/Docker-socket mount.

Run only after other heavy work releases the shared lease. This helper neither
acquires nor retires a host lease or Docker resource. A failed/unknown create or
cleanup remains the supervisor's retained responsibility. The image ID,
dependency installation and cgroup limits cannot be independently inspected from
inside this unprivileged container; those require supervisor evidence. The
helper separately verifies read-only engine/owned files and their exact hashes.

## Fixed inputs and invocation

Create a fresh `/home/container/.amz` as uid65532, mode0700. Do not reuse old
locks, credentials, controls, checkpoints, saves or a cold retained volume.
Copy exact bytes through the bounded owned stdin transport, not a host mount:

- `public-seed.archipelago`, mode0600, the admitted genuine seed.
- `observation-acceptance-input.json`, mode0600, the exact manifest below.
- `observation-candidate/`, mode0700, containing mode0600 exact bytes of
  `profile.v1.json`, `native_yacht_observations.py`, and the pinned
  `native_yacht_effects.py` foundation. Their hashes are compiled into the helper.
- The captured helper at a supervisor-pinned private path such as
  `/home/container/.amz/observation-probe/qualify_native_context.py`.

The manifest has exactly seven keys:

```text
schema:'amz.ap.public-beta.yacht-observation-native-acceptance.v1'
candidateSourceCommit:'7a9a047afd6c38e9bcce4b98053ee43296f9386b'
foundationImageId:'sha256:1b9104acd36cb98950aee35e08c12a70ea3efa78b6a55b90ebaaa1d76ce6fc03'
run:<exact committed-effects run fields, including actual seedName/hash>
roster:[{actorUuid,slotAlias,team:0,slot}, {...second genuine native slot...}]
identity:<exact full Public native runtime identity>
browserBuildSha256:<reviewed build identity; browser itself is not exercised>
```

Use fresh private acceptance UUIDs for synthetic account/control-plane binding
metadata; actual seed names, slot aliases and slot numbers must match the genuine
seed. These metadata identities do not claim real AZAS login or a CP admission.
Never copy old private passwords, HMAC keys, access tokens or control envelopes.
The helper generates unrelated new gateway/observation keys inside the process.

Override the image entrypoint with the fixed Python interpreter and supply only
the explicit consistency marker:

```text
AMZ_NATIVE_OBSERVATION_ACCEPTANCE=private-owned-genuine-context-only
/usr/local/bin/python -I -B /home/container/.amz/observation-probe/qualify_native_context.py
```

Only the optional literal `--describe-seed` mode below is accepted. Do not use the ordinary runtime entrypoint, a mutable
image tag, package install, network download or production account. Source-only
contract checks are separate:

```text
python -I -B -m unittest discover -s amz-runtime/public-beta-observations/acceptance -p 'test_*.py'
```

The existing Linux source discovery also loads these eleven inert contracts through
`public-beta/tests/test_native_yacht_observation_acceptance_contract.py`; no
workflow bytes or actual-image execution are added to the source lane.

### First inspect only real seed metadata

When the old generation receipt does not expose the exact seed name/slot aliases,
do not deserialize the seed on the host or copy a previous private config. Run
the same captured helper with `--describe-seed` inside the admitted owned image.
It uses a separate mode0600 fixed `observation-seed-description-input.json` with
exactly:

```text
schema:'amz.ap.public-beta.yacht-observation-seed-description-input.v1'
candidateSourceCommit:'7a9a047afd6c38e9bcce4b98053ee43296f9386b'
foundationImageId:'sha256:1b9104acd36cb98950aee35e08c12a70ea3efa78b6a55b90ebaaa1d76ce6fc03'
seedSha256:<independently verified genuine seed hash>
```

The same full foundation/candidate/seed checks run before any engine import.
The native pinned `Context.decompress` then produces a bounded whitelist-only
description: seed name/hash/size and the two real aliases/team/slot numbers.
It constructs no Context or native owner, generates no key and returns no slot
data, items, passwords, tokens or controls. The mode writes separate private
`observation-seed-description.json` and `observation-seed-description-private.log`
and emits the metadata JSON with `qualification:false`. It grants no gameplay,
readiness or deployment qualification. The supervisor can use these exact native
metadata to assemble the seven-field full input with fresh synthetic actor/run
UUIDs, then invoke full acceptance in the same still-fresh owned container.

## Actual checks and evidence

Before the first engine import, the helper captures and verifies the existing
runtime artifact, all owned runtime sources, all3539 pinned engine files, hints,
candidate profile/module/foundation, native ABI source and exact seed bytes.
It uses the genuine MultiServer Context, its native `load`/`decompress`/`_load`,
the already reviewed headless composition, real NativeFiles and NativeBarrier.
It creates a normal private native save, with the daemon autosaver disabled.

The existing native observer proves the genuine Context has no connected
endpoints before `mark_ready()` enables the component read probe. **This does
not qualify a serving runtime or listener readiness.** No listener is started.

Both real slots must have start inventory. The producer must return their full
slot data and exact sparse network location maps, excluding the nonnetwork goal.
For each direction, a genuine valid cross-slot location goes through normal
`register_location_checks`; the actual native item tail and unchanged record
prefix must then appear in the receiving producer snapshot. A valid self-item
check additionally proves that remote-true receives the item while remote-false
does not. Unknown/absent compatible locations fail instead of inventing checks.

Wrong seed bytes/name and stale launch identity must be refused. The fixed
authenticated read channel is then exercised against real protected files;
request/response MACs, descriptor hash and consumed-control handling must pass.
An audit hook prohibits socket bind/connect and child process execution.

The create-only result is `observation-acceptance-result.json`, mode0600. It
contains source/seed/component hashes, real transfer metadata, negative cases
and explicit unqualified boundaries. Stdout contains only a bounded metadata
summary and receipt hash. Native diagnostics remain in the private mode0600
`observation-acceptance-private.log`; the helper checks its fresh key material
was not disclosed. The supervisor must capture evidence before retiring its
owned tmpfs/container and attach actual image/resource/cleanup receipts.

A successful run qualifies only this candidate's **actual native Context
observation component** for these exact inputs. It does not qualify the new
runtime image, serving readiness, website authorization, browser gameplay,
completion, current-slot authority, restart migration, save/resume, provider
routing, public cutover or durable recovery. Failures retain private evidence;
the helper performs no automatic stale-file repair or profile promotion.

Failure reporting distinguishes Context construction, native load, `init_save`,
empty-listener checks, initial barrier readiness, ABI enrollment, observation
construction and first snapshots. The former single `genuine_native_seed_load`
stage covered all these operations and cannot identify a particular failing
call in historical evidence. The candidate's native tuple normalization is a
source-identified compatibility fix; actual acceptance still needs a new run.

Failure stderr adds only a closed exception-type name (or
`UnclassifiedException`) and at most16 captured-code frames. Each frame has a
fixed logical source label, a function name present in that verified source's
AST, and an in-range line number. Only the helper, captured foundation/candidate
modules and four independently inventory-checked native files are enrolled.
Unregistered frames and private absolute paths are omitted. The bounded walk
reads no exception message, arguments, representation, locals, source lines or
raw log text. Pure contracts exercise secret-bearing exceptions and metadata
bounds without importing an engine. Native logs remain private as above.

The actual native receipt explicitly records `nativeContextOnly:true`, while
`cpRosterAuthority`, `currentWebsiteAuthorization`, `browserGameplay`,
`imageQualified` and `productionAdmitted` remain false. Actor/control-plane UUIDs
are synthetic private acceptance metadata joined to genuine native seed slots,
not evidence of AMZ admission. The browser hash is binding metadata only and does
not qualify a browser build or browser gameplay. Description mode additionally
records `seedMetadataOnly:true` and `nativeContextConstructed:false`.
