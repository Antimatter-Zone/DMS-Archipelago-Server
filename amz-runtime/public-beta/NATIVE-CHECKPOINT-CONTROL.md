# Public native save and terminal control source

This additive Server-only adapter composes the verified native Context with
the custody primitive. It does not import an engine as a source-test side
effect, open a listener, change Member source, publish an image, register an
operator adapter, restore a game or reopen admission. All native/game/image/
production acceptance flags remain false. The production control caller and
its current CP/lifecycle/Play authority are still separate required work.

## Serialized native save replacement

The Public loader preserves the exact native Context class, `get_save()` and
ordinary `save()` semantics. It replaces only the Public `_save` and
`_start_async_saving` implementation. The upstream daemon and atexit writer are
not started: their uncoordinated direct file writes could overlap capture.
Instead, initial save, active-game dirty saves every60 seconds, final ordinary
shutdown save and explicit checkpoint capture use one loop-owned writer.
Periodic saving remains available; a fixture does not qualify actual sessions
or promise an RPO. This is local game persistence, not scheduled off-node backup.

`NativeSnapshots` captures its owning native loop thread and refuses any other
thread or an unexpected native saver thread. Snapshot creation calls the exact
verified `Context.get_save()` and serializes synchronously, without an await
that could interleave native client handlers. The encoder uses native default
pickle protocol and zlib format, with16MiB compressed and64MiB expanded limits.
The fixed `/.amz/public-seed.apsave` writer requires the existing NativeFiles
owner, private0600/single-link metadata and no pending prior write. It fsyncs a
new exclusive file, verifies identity, replaces the save, fsyncs the directory
and reads back exact bytes. Uncertain IO retains the owner lock/evidence.

The native loop polls due saves explicitly; no timer/thread starts on import.
Ordinary shutdown closes admission and the listener before waiting for the
native connection handlers, control pump and native task to settle. Only then
does it take the final synchronous save. The drain has a ten-second bound;
unknown drain retains the owner lock and reconciliation state, makes no final
save claim and fails shutdown. A fixture does not qualify real engine shutdown.
The Public native loop installs explicit SIGTERM/SIGINT stop callbacks before
starting native tasks. The pinned upstream later installs its own listener-stop/
exit-event callbacks, which also reach this drain. Interruption during earlier
verification/import is refused startup; it is not a graceful-save promise.
A failed save does not clear dirty progress. Terminal capture disables further
periodic/final writes once admission closes, preserving the custody snapshot.
The read-side codec bounds decompression, rejects truncated/multiple/trailing
zlib streams, limits pickle operations, requires final STOP, and requires the
verified native restricted loader callback. It has no `pickle.loads` fallback.
Actual native restricted restore and old-master handling remain unwired.

## Separate fixed lifecycle control channel

Gateway HMAC/control/ACK v2 and the exact Portal provenance copies are unchanged.
The new Server lifecycle channel uses only these fixed private files:

| File | Writer | Limit |
| --- | --- | ---: |
| `/.amz/public-runtime-control.json` | Protected operator only | 64KiB |
| `/.amz/public-runtime-operation.json` | Native runtime only | 64KiB |
| `/.amz/public-runtime-ack.json` | Native runtime only | 64KiB |

The runtime owner uses the same lock/directory FD and exact canonical bounded
JSON/atomic fsync writer. Pending operation/ACK files refuse automatic startup.
Fresh loader initialization refuses any stale save/status/custody/migration or
lifecycle file. No ordinary request chooses a filename, backend or serializer.
The Public Panel client does not yet expose these new names.

The exact `amz.ap.public-beta.runtime-control.v1` request is:

```text
schema, operationId:UUID, command:'checkpoint_and_hold',
identity:<exact full Public runtime identity>,
gate:<existing retained idle gate>, issuedAt, expiresAt
```

The lifetime is at most eight seconds, with a nonextendable monotonic deadline
captured from the remaining wall-clock lifetime at first valid observation.
That same deadline remains in force for in-process lost-ACK replay. Pins for the seed/runtime artifact/pack
come from the verified protected startup configuration, not the control packet.
The operation UUID is also the immutable native checkpoint UUID. The command
hash is SHA-256 over schema, newline, then canonical complete request bytes.

The controller requires the exact held idle gate and authoritative native zero,
not a cached status count. It fsyncs an operation intent before any admission
closure or serialization. It then calls custody capture with the real native
snapshot, which durably closes admission and publishes the atomic native-save
plus barrier container. Only after that fsync/readback does it persist a sealed
operation and publish metadata in `amz.ap.public-beta.runtime-ack.v1`:

```text
schema, operationId, commandSha256, identity, observedAt,
result {state:'sealed'|'unknown',custodySha256:SHA|null,
        bytes:integer|null,admissionHeld:true}
```

No save bytes, backend password or player/account credential appears in ACKs.
The native/protected wall clocks and captured monotonic deadline are rechecked
after intent, snapshot and ACK durability; clock rollback/expiry returns no successful operation. The
future operator must also check its own current deadline/authority after ACK
read and validate exact operation/hash/identity. File visibility alone is not a
current CP grant, provider-stop or encrypted archive receipt.

Only one terminal operation exists per runtime launch. A lost ACK can reproduce
the exact sealed outcome after verifying its durable custody hash and held
gate. Preparing/unknown intent returns unknown and never reruns the serializer;
another operation ID or changed body conflicts. Remote or filesystem uncertainty
never releases capacity, deletes a save or reopens a native permit.

The next protected step may stop the exact old process, bind its terminal
journal in the reviewed migration manifest, and prepare a new held process.
Actual restore, original idle-history migration through a native listener,
browser-state coordination, combined ciphertext budgets and explicit current
Play-authorized reopen remain open. Source tests are synthetic local adapter
and codec evidence, not normal game-session or native-engine qualification.
