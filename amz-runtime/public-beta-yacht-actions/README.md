# Fresh Yacht action runtime — immutable source composition

This is a new, complete fresh-start image recipe, not an injected module candidate.
Its normal loader enrolls the strict Yacht packet policy, exact native observation
reader and committed-effect controls alongside the existing gateway barrier and
serialized native save owner. All qualification flags remain false. No build,
native listener, actual image acceptance, gameplay or production admission is
established by the source tests. Historical fresh79 and held-restore f466 files,
profiles and provenance are unchanged.

`source-foundation.v1.json` pins26 exact Server Git objects, including the original
fresh loader/helper/engine dependency metadata and the existing observation/effect
modules. The new builder captures bounded regular/single-link source bytes once,
checks SHA256 and Git object identities, and supplies the pinned helper from that
captured map. The runtime executes captured verified source bytes; it never imports
another checkout. A new artifact schema `amz.ap.public-beta.yacht-action-runtime.v1`
has a separate execution profile, exact19-file owned inventory and source provenance.
The compatible world-pack hash cb365 remains distinct from this execution-profile
hash. Artifact/image digests are bound by external protected receipts, never included
circularly in their own content. Keep all engine, wheel and Node notices; notice
presence does not override the existing redistribution/license qualification gates.

Default `build.py` is offline/source-only. Explicit `--prepare --cache ABS --output ABS`
requires a clean committed Git source with matching captured blobs and a new output
outside the checkout/cache. The reviewed cache contains SHA-addressed engine ZIP and
eight locked wheels. Every input is hash/size/path checked; output is built from the
captured bytes only, retaining notices. No network fetch, dependency installation,
Docker or engine import occurs in the builder. The separate Dockerfile uses the
existing pinned Python3.12/Node24.20 bases and offline hash-locked wheels under UID65532.

## Protected boot contract

The exclusive operator creates exactly these three files in the runtime-owned
`/home/container/.amz` directory (0700), all regular0600/single-link, before start:

- `public-runtime.json`: schema `amz.ap.public-beta.yacht-native-configuration.v1`,
  profile `public-yacht-actions-fresh-v1`, exact runtime identity, independently
  admitted `runtimeArtifactSha256`, `executionProfileSha256`, compatible world-pack,
  engine commit/inventory, seed SHA, private backend master and approved port;
  `journalMode:'initialize'` and `requiredCheckpointSha256:null` only. Immutable
  `run` binds policy/environment/epoch/room/attempt/seed/configuration revision,
  seed SHA/name; the generated roster binds AMZ actor/alias/team0/slot exactly;
  `browserBuildSha256` names the separately admitted matching client.
- `public-seed.archipelago`: exact reviewed seed bytes, bounded16MiB, retained and
  loaded through the captured bounded restricted native decoder. This fresh
  action profile enforces the stricter512KiB retained-seed cap below.
- `public-yacht-keys.json`: schema `amz.ap.public-beta.yacht-runtime-keys.v1`, exact
  runtime identity/artifact SHA and canonical `runSha256`, distinct `observationKey`
  and `effectsKey` (32-byte lowercase hex). They cannot reuse each other, known raw,
  hex/base64url master forms, the master hash or the native connect-derived key.
  Protected operator composition separately excludes other service credentials.

No keys are baked into the image or passed in argv/environment. Native child raw
stdout/stderr is bounded/drained but never exported by the launcher. Active control
instances clear their bytearray keys on close; this is not a secure-erasure claim
for every Python/string/caller copy. Key custody and actual boot producers remain
protected operator responsibilities, not authority inferred from hashes or mode bits.

Every preexisting save/journal/ACK/control/lock/pending/unknown file or directory
refuses a fresh start. Failure never wipes, adopts or reinitializes a run. The owner
lock and gateway journal are create-once; effects enrollment requires a missing
effects journal and exact seed/Context/roster. Admission opens only after synchronous
control enrollment; any enrollment failure closes it before another native await.

## Native packet and lifecycle policy

The image admits only Yacht slots. Before the native server's sequential packet
dispatch loop, a complete bounded frame is validated (text UTF8<=256KiB,1–32 packets,
no duplicate JSON keys). Every packet must match a closed `Connect`, `ConnectUpdate`,
`Sync` or `GetDataPackage` shape. Native Version0.6.8 conversion is retained without
accepting string/bool coercion. Tags stay `['AP']` and received-item handling stays7;
the gateway/normal hooks still require the exact prepared slot credentials and
current connection phase. Clients cannot choose a weaker profile using Origin,
tags, game or ConnectUpdate. Mixed batches containing any other command fail before
any native decode hook, Connect consumption or command dispatch.

`LocationChecks`, `StatusUpdate`, `Say`, `Set`, `Bounce`, scouting/hints/notifications
and unknown commands are denied. Only the independent authenticated committed-effect
control can call the pinned native check/goal handlers. The existing browser's direct
checks/goal and self-Bounce heartbeat are incompatible: a new admitted browser action
adapter must render only CP-committed state and use the approved read-only channel.
Generic native runtime/client profiles are unchanged.

Controls poll on the one native event loop with the normal gateway pump and serialized
saver. Idle holds suspend observation/effect delivery rather than reopening admission.
Shutdown closes admission, stops control polling, zeros active control keys, drains
the listener/handlers and finishes the serialized save. Unknown teardown retains
native owner/journal evidence. An effects ACK still means observed native memory,
not save durability; its historical wire remains unchanged. Observation ACKs retain
their existing independent HMAC.

## Enforced native plaintext workspace budget

`native_budget.py` is part of the immutable owned inventory. The aggregate cap is
3MiB, including a fixed256KiB metadata allowance and complete current/new-pending
replacement overlap. Fixed per-file caps are seed/save512KiB each; gateway and
effects journals512KiB each; observation ACK512KiB; gateway/effects ACK and each of
three external control files64KiB; status/config16KiB each; keys4KiB; owner lock1KiB.
These maxima need not all fit at once: aggregate refusal is authoritative.

The guard reserves the lock before its fixed captured constructor can publish;
wraps the real NativeFiles instance `_replace` before journal initialization;
wraps the actual binary NativeSaveFiles instance before the first initial save;
and publishes status through that same guarded owner. It audits the retained
FD root before publication, counts the full old target plus new pending payload,
and rejects over-cap bytes BEFORE opening a temp file. Non-save growth must also
leave512KiB headroom for the final save. External cooperating control producers
get a fixed current+pending reservation even when their files are absent; they
must enforce their64KiB limits independently. Unknown files, pending evidence,
links, directory replacement, IO or capacity refusal mark the owner uncertain
and retain evidence. No evidence is silently deleted or compacted to make space.

The current operator Panel file client writes directly to the final path and then
chmods it; that API is NOT a proven atomic publication producer. During such a
write, a reader can observe zero/partial bytes or transient permissions and must
hold rather than parse/acknowledge uncertain control state. This runtime deliberately
does not relax those checks. Playable observation/effect/gateway delivery remains
unqualified until a separate protected atomic publication mechanism is implemented
and actually proven. The reserved external byte allowance is not that proof, and
ordinary Panel writes cannot satisfy this activation gate.

Engine settings/cache/output use a separate create-once0700 directory under a
kernel-observed `/tmp` tmpfs bounded64MiB. The image root is required read-only.
Those ephemeral files cannot accumulate unnoticed in the retained native root.
The workspace cap is a logical plaintext bound, NOT a physical storage permit,
encrypted owner-budget proof or claim about filesystem metadata allocation.
Windows data-audit fixtures cannot bind production writers; actual writer guards
require the Linux FD and real NativeFiles type.

Production quota admission remains CLOSED. A future protected encrypted native
capsule producer must enforce actual ciphertext+metadata<=4MiB per bundle and
current+replacement<=8MiB before CP may enroll an8MiB native reservation. That
producer/custody proof is not implemented here. CP state, operation history,
outbox and all other retained data/overlap must still fit the combined16MiB owner
and1GiB service budgets. Neither these limits nor a local component image test
qualify that complete quota service.

Restore and old `checkpoint_and_hold` are deliberately not enrolled. That capsule lacks
the effect journal; this runtime refuses its control file. A new capsule/migration must
preserve effect commits/journal, actual native save/barrier and CP committed item prefix,
with exact old-stop evidence before any restart/reopen. Never borrow f466 qualification.

## Checks and actual qualification still required

The new test is discovered by the unchanged Public source workflow:
`python3 -I -B -m unittest discover -s amz-runtime/public-beta/tests -p 'test_*.py'`.
It uses data/source and owned-filesystem fixtures: four allowed packets, whole-frame
rejection, Version/coercion/stream bounds, boot/key binding, captured artifact closure,
real Node/Python artifact interoperability and normal loader enrollment. Budget tests
cover combined/overlap/headroom arithmetic and real owned file audits. Five Linux-only
cases exercise actual JSON/binary/status publications, pre-open refusal and uncertain
owner retention; Windows reports explicit platform skips for those. It imports no
engine and prepares no context.

After source CI, Root must separately qualify the actual assembled image/entrypoint:
real listener/two clients, mixed-frame no-partial-effects, authenticated observations,
signed committed-effect delivery/replay, serialized shutdown and retained failure
evidence. Later CP action/outbox and new browser integration plus genuine play/resume
remain required; neither an image nor a zero-client Context test closes gameplay.
