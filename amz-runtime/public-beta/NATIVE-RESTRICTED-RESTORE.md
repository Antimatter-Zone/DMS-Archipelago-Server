# Separate held native restore source

This four-path additive source slice is not a restore entrypoint, image,
operator adapter or runtime registration. `native_restore.py` imports no
Archipelago engine and starts no thread, timer or listener. The fresh runtime
at79e2b0d2, its loader/artifact builder/profile and all exact Portal provenance
copies remain unchanged. The new `native-restore-profile.v1.json` is separately
SHA-pinned in the helper; its registration and acceptance fields remain false.

The intended production composition must verify the separate artifact, complete
owned inventory, exact548 engine inventory and protected configuration before
any engine import. Only that composition may supply the real verified
`Utils.restricted_loads`, native `Context` and existing `NativeSnapshots` owner.
The current fresh loader never selects this helper or falls back to it.
Actual native restore, listener startup and browser resume are not proved by
the source fixtures. They remain qualification and integration work.

## Protected restore operation

`restore_native` is synchronous, on the snapshots' owning thread, before any
native listener, handler, endpoint or saver thread exists. It takes the existing
concrete custody/native-file owner, an exact external profile pin, migration
manifest pin, seed bytes, old-stop receipt pin, target runtime/pack pins and
new identity/master. Those are protected composition inputs, never browser
parameters. There is no missing-journal bootstrap or native `init_save` fallback.

The existing custody migrator independently rereads and verifies the fixed
manifest. It binds the actual seed/capture/post-stop journal, old/new identity
and stop receipt; advances launch and credential identity; and installs a new
held journal with the original generation and initial-ready/last-disconnect
basis. The helper adds one nonextendable monotonic deadline from the remaining
five-minute manifest lifetime, in addition to the migrator's post-IO wall-clock
checks. File locks and held/unknown state remain on any uncertainty.

The native codec has the existing16MiB compressed,64MiB expanded and bounded
pickle-operation limits. The decoder must be the verified native restricted
loader; there is no automatic `pickle.loads` fallback. Fixtures use only
explicit synthetic standard-library data/decoder to avoid importing an engine.
The exact native save shape/version and seed-loaded `connect_names` must match.

Pinned548 `Context.set_save` restores `game_options.password`, admin password
and item-cheat configuration. Consequently this helper copies only that option
mapping before the call and replaces its password with the new protected master,
keeps admin password empty and forces item cheats off. Reusing the old master
is refused. No old credential is supplied to `set_save` and no game-progress
field is rewritten. Both old and new master values are log-redacted before the
native call. Failure is reduced to a fixed error rather than raw save/exception
contents. The successful private `RestoredNative` handle retains redaction until
the composition explicitly closes it after the native process/handlers drain.

After `set_save`, the helper checks protected settings/quiescence and the exact
migrated journal again, publishes the rotated native save through the existing
atomic file/fsync/readback owner and restricted-decodes its readback. Expiry or
clock rollback after native/file IO returns no receipt; it cannot undo an
already durable target, which stays held for protected reconciliation. A failed
attempt seals the snapshots object, poisons its owner and cannot retry in that
instance. Successful source metadata describes `restored_held` only. It binds
the exact migration/old-stop/target-artifact/pack/seed/custody pins, restored
save hash/bounds, new identity and idle basis, without passwords or native
progress bytes.

## Later entrypoint, native ready and explicit reopen

The separate restore entrypoint/artifact composition is not in this cohort.
It must enroll these exact bytes in a new owned inventory/profile, validate all
protected inputs before importing548, install the existing Public HMAC hooks and
loop-owned periodic saver, and call this primitive before opening a listener.
The old fresh profile continues to reject every existing save/journal/migration.
Old process lock deletion or adopting an uncertain lock is not implemented here;
an exact positively stopped process and the protected custody transfer are
mandatory and may not be inferred from file absence or a timeout.

After restoring, construct the existing NativeBarrier with the returned held
state and new master. Its authoritative observer must report actual native zero,
with no pending handler, and its exact listener must be serving before ready is
recorded. `mark_ready` preserves the existing idle basis; a new process must not
replace it with startup time. A ready listener still cannot consume a prepared
Connect through the retained idle gate.

A later explicit reopen protocol must bind the exact held gate, new identity,
seed, generation and original idle history to a freshly authorized CP slot/Play
operation. It needs an actual current grant-reference/resource ledger adapter,
retained Play handoff and native atomic barrier on the same event loop, with a
nonextendable deadline and durable intent/ACK. It must remove only the named idle
gate after those checks, preserve revocations and every idle-clock field, and
retain uncertainty on lost outcomes. This source adds no reopen command, fake
current callback, default authority or blanket clearing of gates. Browser-state
custody, combined encrypted budgets, real provider stop/restore and genuine Yacht
play/resume remain separate required work.
