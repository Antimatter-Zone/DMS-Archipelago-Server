# Committed Yacht effects candidate

This separate source-only profile has no loader, listener, image recipe, polling
registration, signing endpoint or production authority. Existing fresh79 and
held-restore f466 profiles, their Portal provenance copies and evidence remain
unchanged. The existing Public source workflow discovers the new pure tests in
`public-beta/tests/test_native_yacht_effects_candidate.py`; tests import no engine.

## Protected enrollment and private files

A future reviewed loader must first verify the complete engine inventory, this
profile/module/foundation hashes, protected configuration, seed and fixed roster
before importing any engine. It must then enroll the exact already-loaded
MultiServer548 module with captured LF source SHA
`e157abab8a56351d58f1cf5a84c6c2a9144d295956d6be08cbd5811c7a2932de`.
The helper compiles source without executing it and compares exact function code
for `register_location_checks`, `update_client_status` and
`Context.on_goal_achieved`. Arbitrary callback/name selection is unavailable.
Native status accepts only the exact enrolled `MultiServer.ClientStatus` type
shared with the verified `NetUtils` module (the pinned five-value IntEnum), or
plain integers with those same five values. Booleans, foreign enums and arbitrary
integer subclasses are refused. Normal goal application uses CLIENT_GOAL itself.
This check supplements the verified loader, not a replacement for engine and
dependency verification or isolation from privileged in-process code.

The helper reuses the existing `NativeFiles` owner/lock and private directory FD.
Only the following fixed names under `/home/container/.amz` are admitted:

| File | Writer | Maximum |
| --- | --- | ---: |
| `public-yacht-effects-control.json` | Protected dispatcher | 64KiB |
| `public-yacht-effects-journal.json` | Native helper | 2MiB |
| `public-yacht-effects-ack.json` | Native helper | 64KiB |

`initialize_effects` is a separate protected create-only enrollment. Construction
requires the existing exact run/roster/launch journal. Missing journals, foreign
runtime identity and pending journal/ACK writes refuse; no empty fallback,
automatic migration, stale-lock deletion or gate reopen exists. Restart/restore
needs a separately reviewed protected custody migration/enrollment; this module
does not provide it. The future lifecycle capsule must carry this journal along
with native/browser state and bind its hash. Native lock/owner/mode/single-link,
same-FD bounds, exclusive temporary file, fsync, replace, directory-fsync and exact
readback behavior comes from the pinned concrete owner.

## Immutable committed action versus fresh delivery

The independent32-byte protected key must belong only to the trusted commit
signer/dispatcher and this native profile. No request chooses a key/path/backend.
Known master/hash reuse and the all-zero key refuse; composition must also reject
reuse of any other resource/API/vault secret it possesses. No key is shipped.
The signer must authenticate only an already durable atomic browser-checkpoint
plus effect-intent commit. Browser-supplied MACs are never a substitute for that
server-side transaction or authorization. A committed action remains valid after
sign-out/takeover, but its historical effect authority cannot admit a connection,
change roster, grant Play or mutate a credential/idle baseline.

The exact immutable definition is:

```text
schema:'amz.ap.public-beta.yacht-committed-effects.v1',
run:{appVariant,policyId,environmentId,dataEpoch,roomId,attemptId,seedRevision,
     configurationRevision,seedArtifactSha256,seedName},
player:{actorUuid,slotAlias,team:0,slot},
commitId:UUID,commitRevision:positiveInteger,checkpointSha256:SHA,
effects:{checks:sortedUniqueYachtLocationIds[<=1000],goal:boolean}
```

The stable proof is hex HMAC-SHA256(key, immutable-schema + newline + canonical
definition). Runtime launch, allocation and rotating Play/credential revisions
are excluded from that definition. The run, immutable roster and exact native
seed still bind every effect. The journal retains only the latest commit per
slot plus its bounded cumulative check set/goal; it never grows per click.
Strictly advancing revisions may coalesce multiple committed actions. They must
preserve every earlier check and goal; resetting a score sheet cannot drop them.
Same revision requires identical logical bytes. Superseded revisions refuse
without pretending to prove their outcome. The CP retains logical commit receipts
and must never reuse commit IDs or relabel a seed/profile/image across attempts.

The exact delivery envelope is:

```text
schema:'amz.ap.public-beta.yacht-effects-control.v1',deliveryId:UUID,
identity:<exact current full native runtime identity>,issuedAt,expiresAt,
commit:<immutable definition>,commitMac:SHA,deliveryMac:SHA
```

`deliveryMac` is hex HMAC-SHA256(key, delivery-schema + newline + canonical
envelope without deliveryMac). Sorted-key compact UTF-8 canonical JSON is used
throughout. Lifetime is at most5 seconds; remaining wall lifetime becomes a
nonextendable monotonic deadline, retained for same-delivery retries. Current
owner/thread, native binding, clock floor, lifetime and held-idle exclusion are
checked before/after durability and native application. Renewing transport uses
a NEW delivery UUID and dates for the SAME immutable commit/proof, never a reroll.
No current-account callback or current Play grant is used to erase a previously
authorized committed action.

## Normal native application and ACK meaning

Application stays on the owning native event-loop thread and contains no await.
It requires ready/nonuncertain native observation and refuses any held idle gate.
Revocation gates may remain held: historical committed effects do not restore
player access. The helper never changes gateway preparations, connected counts,
connection generation, original idle basis or admission gates.

Before normal native mutation, a canonical intent is durably written/read back.
Only missing committed checks go through the exact normal
`register_location_checks(context,team,slot,locations)` function. Goal30 goes
through normal `update_client_status` and `on_goal_achieved`; the exact pinned ABI
needs only an immutable internal team/slot address. That address is not a fake
client connection or a native-client acceptance claim. Ordinary native goal
collect/release behavior remains the pinned normal behavior, not a generic
command/packet API. Unknown locations are refused rather than silently ignored.

The helper re-observes actual native checks/goal, durably records observation,
then publishes metadata-only `amz.ap.public-beta.yacht-effects-ack.v1`:

```text
schema,deliveryId,deliverySha256,identity,commitId,commitRevision,
definitionSha256,observedAt,
result:{state:'observed',journalSha256:SHA,nativeSaveDurable:false}
```

This ACK proves durable intent/observation journal plus observed AP MEMORY, not
an `.apsave` disk write, completed archive, browser ACK, provider stop or quota
release. Keep the cumulative effects for the seed. A retry under fresh delivery
always re-observes native state and reapplies missing committed effects even if
the journal previously said observed. Repeated checks/goal use native monotone
semantics. A native rollback therefore cannot be hidden by a cached success flag.

Expiry before mutation leaves the durable intent for exact renewed delivery.
Partial handlers or late/uncertain application/ACK IO retain unknown intent and
close native readiness with uncertainty; protected recovery is required. Even
if an ACK file became visible before a late refusal, the caller must enforce its
own exact delivery/deadline/authority checks and must not adopt a late proof.
Polling is explicit and single-loop; no timer begins on import. Shutdown clears
the in-memory independent key and refuses further commands.

## Remaining gates

Required next work is actual CP atomic checkpoint/effect commit signing,
server-owned dispatcher, protected key provisioning, new verified profile
loader/artifact/image enrollment, gateway rejection of precommit Yacht writes,
exact native/custody journal migration and lifecycle drain ordering. Lifecycle
must block new slot commits and settle committed effects BEFORE taking the idle
fence; this helper cannot write through that fence. Real engine invocation,
crash/power-loss recovery, two-browser action/save/resume and production routing
are unqualified. All profile acceptance/registration flags remain false.
