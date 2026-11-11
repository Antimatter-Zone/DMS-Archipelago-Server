# Public native checkpoint custody source

`checkpoint_custody.py` is a Server-owned source primitive for the exact Public
barrier/file-owner cohort. It imports no AP engine and starts no task. The
existing loader still accepts only explicit fresh initialization: it does not
silently select restore, migration or fence reopening. All artifact acceptance
flags and all profile closed gates remain false. This is not a completed
native save/resume, provider stop or encrypted archive implementation.

## Fixed private files and ownership

The concrete `CustodyFiles(NativeFiles())` wrapper uses the existing native
owner lock and directory FD. It takes no path, storage ID or root argument.
It requires the same Linux directory ownership/modes, single-link0600 files,
bounded same-FD reads and regular non-symlink entries as the native journal.

- `/.amz/public-native-custody.amzc`: native-owned opaque checkpoint container,
  at most16MiB including its header and barrier. Protected operator read only.
- `/.amz/public-runtime-migration.json`: protected operator canonical JSON,
  at most16KiB, native read only under an independently supplied expected hash.

Both paths are relative to the fixed `/home/container` volume. Pending custody
writes are exclusive0600 files; publication fsyncs file then replaces the fixed
name, fsyncs the directory and verifies exact bytes/inode before returning.
An uncertain write poisons the shared owner, preserves pending/renamed evidence
and retains its lock. No stale-lock cleanup, missing-file initialization or
success on an unavailable directory fsync exists. A failed operation never
authorizes provider release or deletion of the previous encrypted archive.

## Terminal native capture

`capture(files, barrier, gate, ..., native_snapshot=...)` requires a genuine
ready barrier, exact retained idle gate, authoritative empty native observer,
no in-flight handler, all preparation rows closed, and the same generation and
original initial-ready/last-disconnect basis. It durably closes native readiness
before invoking the synchronous serializer. Failure leaves admission closed.

The primitive deliberately has no default serializer. The separate
[native checkpoint adapter](NATIVE-CHECKPOINT-CONTROL.md) now binds the exact
`Context.get_save()` in Public source and replaces overlapping thread writes
with an equivalent bounded atomic periodic saver. The upstream `save(True)`
return alone is insufficient. Real native codec/session qualification and
protected restricted restore integration remain open.

Capture verifies the unchanged barrier before and after the trusted serializer
and durable publication. The container is `AMZC1` plus NUL, a four-byte big-endian
canonical-JSON header length, that header, exact native-save bytes, then exact
canonical barrier bytes. The header pins both payload lengths/hashes, schema,
checkpoint UUID, full runtime identity, runtime artifact/world-pack/seed hashes,
retained gate, original idle history and capture time. No packet chooses a path
or serializer. Neither a self-chosen hash nor this file grants authority.

The local16MiB container bound is only a component guard. The protected CP and
archive composition must reserve the prospective combined encrypted seed,
native/barrier and all browser-state bytes, replacement/encryption overhead,
one-owner/7-day save and global1GiB budget before claiming Save & close.
Failure must preserve the capacity charge and last good encrypted checkpoint.

## Explicit protected migration

`migrate(files, expected_manifest_sha256=..., ...)` reads only the fixed migration
file. The expected hash, target artifact/pack pins and old-stop receipt hash are
protected boot/composition inputs, never browser or request-selected authority.
Its canonical `amz.ap.public-beta.native-migration.v1` manifest has exactly:

```text
schema, operationId, oldIdentity, newIdentity,
custodySha256, seedArtifactSha256, nativeSaveSha256, barrierSha256,
stoppedBarrierSha256, stoppedBarrierRevision, stoppedBarrierClockFloor,
idle {connectionGeneration,provenInitialReadyAt,provenLastDisconnectAt},
runtimeArtifactSha256, worldPackSha256,
targetRuntimeArtifactSha256, targetWorldPackSha256,
oldStopReceiptSha256,
newHold {gate,request}, issuedAt, expiresAt
```

An approval lasts at most five minutes. The environment, epoch, room, attempt
and seed identity must remain unchanged. Runtime launch identity must change,
credential epoch must advance and allocation revision cannot decrease. Keeping
the allocation requires keeping the server identity. Old preparation proofs
and control IDs are not replayed into the new process; the new identity/master
must invalidate them. Configuration/browser saved bindings remain a separate
protected parent responsibility.
The trusted composition supplies a clock callable, not one request timestamp.
The module resamples it after file reads, immediately before journal commit,
after commit/fsync and after readback. Expiry or clock rollback returns no
success proof. If durability crossed expiry, the target remains held and the
operation requires protected reconciliation rather than claiming completion.

The container's barrier digest binds capture. The separate post-stop digest,
revision and clock floor bind the exact journal observed after the protected
operator positively stopped the exact old process/provider resource. This
module verifies the supplied receipt binding; it does not contact Panel,
inspect processes or turn file absence into stop proof. Graceful shutdown may
advance only journal revision/clock/control history: native generation, gates,
preparations and original idle basis must match capture exactly. Unknown or
nonterminal state refuses migration.

Migration requires an existing journal equal to that exact post-stop journal,
or the exact already-durable migration result after a lost acknowledgement.
Later progress cannot be rolled back by replaying an old manifest. The target
journal preserves the original generation and idle clock, keeps readiness
false, and installs a fresh identity-bound retained idle hold. No new readiness
timestamp replaces the original basis. The exact native state is returned only
to private composition; no public status or save-completion claim is emitted.

The next reviewed integration must restore the native save with exact source,
seed/slot identity and bounded restricted decoding; override and redact prior
backend credentials; prove the actual listener/observer; and explicitly reopen
the retained hold only after current CP/grant/Play authority permits it. Reopen
must not reset the idle clock. Missing/uncertain stop, storage, native or Play
evidence stays held and charged. None of those steps is implemented by a fake
production default here.

## Evidence boundary

Source fixtures exercise real barrier data plus synthetic serializers/storage,
hash/tamper/epoch/idle/replay refusal, lost acknowledgements and graceful-stop
journal succession. Separate Linux-only fixtures exercise the concrete binary
file writer and fsync failure retention. No AP engine import, image build,
actual native codec, provider process stop, browser checkpoint, encrypted
archive, power-loss or real game/resume qualification is claimed.
