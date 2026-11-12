# Native Yacht observation candidate

This Server-owned source candidate supplies the native fact producer needed by
server-authoritative Yacht actions. It performs no engine import, network
request, background polling, loader enrollment, image build or registration on
import. Existing fresh79, held-restore f466 and committed-effects profiles and
their qualification evidence remain unchanged.

The future reviewed loader must verify all engine/dependency/owned bytes before
imports, then enroll this module and its exact pinned foundation modules from
captured bytes. The profile binds Archipelago0.6.8 commit
`54803be064fc7e80c4628777ed0b46a9390f255f`, full MultiServer and NetUtils hashes,
module bytes and the existing fixed native-file owner. No sibling Portal code or
checkout is imported. Source tests use an explicitly synthetic native module;
they do not qualify an actual engine, image or playable room.

## Genuine native facts

`VerifiedYachtObservationABI` compares exact compiled native code for
`Context.decompress`, `Context._load`, `get_start_inventory`,
`get_received_items` and `send_new_items` against captured pinned MultiServer
source. Named tuple identities and normal slot types must come from that enrolled
module's NetUtils. These checks supplement the verified loader; they do not
isolate the process from arbitrary privileged in-process code.

`YachtObservationControl` requires the exact installed seed bytes, immutable
generation run and actor/alias/native-slot mapping, current full runtime identity,
and exact approved browser build hash. It hashes the seed, decodes it through the
enrolled native decompressor, and joins its roster, full slot data, network
location maps and start inventory to the actual already-loaded Context. It does
not substitute hashes or browser-supplied DTOs for native facts. The initial
profile admits only one-team, Yacht-only, nongroup player rosters; item-link
groups and other games require another explicit profile.

The producer uses only real network locations from the seed's LocationStore
mapping. Sparse checks are preserved; the nonnetwork goal event is excluded.
The `items_handling=7` stream is start inventory followed by
`received_items[(team,slot,True)]`, preserving order and every native record's
item, location, source player and flags. The remote-false stream is never used.
Names come from the native Yacht item map and must be understood by the pinned
Yacht model. Missing start copies, unknown items, truncation or any changed
record prefix refuse, even when the replacement records have identical names.

Each descriptor includes the action binding, full slot data, sparse location
IDs, complete native item records, item-handling mode/start count, and the exact
`amz.yacht-dice.item-observation.v1` names/hashes consumed by the reducer. Current
launch, ready/nonuncertain native state and owning event-loop thread are checked
before/after each snapshot. A held idle fence refuses reads. Revocation does not
erase historical native facts or independently authorize player access.

## Fixed protected read channel

The optional explicit `poll_once()` reads only
`/home/container/.amz/public-yacht-observation-control.json` (64KiB) and writes
`public-yacht-observation-ack.json` (1MiB). It reuses the concrete NativeFiles
directory FD, owner lock, same-FD bounds, single-link/mode checks, exclusive
temporary publication, fsync and exact readback. Pending observation ACK writes
require protected reconciliation; they are never deleted or adopted.

Requests have exactly schema, requestId, current identity, actorUuid, issuedAt,
expiresAt and requestMac. No request can select a path, slot number, observation,
seed, build, callback or key. A separately provisioned32-byte HMAC key belongs
only to the private operator reader and this native profile. It must differ
from gateway/effects/API/vault keys; the helper rejects known master/hash reuse
and uniform/all-zero material, and composition must check its other secrets.

Request MACs use HMAC-SHA256 over the control schema, newline and canonical
unsigned request. ACKs bind the exact request hash, current runtime identity,
observation time, original expiry, descriptor hash and full descriptor. Their
responseMac uses the separate ACK schema domain over the unsigned ACK. Compact
sorted-key UTF-8 JSON with bounded safe integer/Unicode values is canonical.
Both sides enforce a maximum5second lifetime. Same-request retries retain the
original monotonic deadline; they cannot renew it. A consumed control file is
ignored by polling after its ACK; direct expired replays refuse. The private
reader must verify the MAC, identity, original deadline and descriptor hashes
before passing native facts to the control plane. A hash alone supplies no
authority. ACKs never contain AP credentials, website grants or access tokens.

This is read-only with respect to native gameplay. It mutates no received item
lists, native checks, statuses, connection generation, idle basis or game save.
The private ACK file is not an AP save, browser checkpoint, current membership
decision, Play grant or durable recovery proof. File/persistence/late failures
never produce an accepted observation; the caller must reject a late ACK even
if its file became visible. Closing clears the in-memory channel key.

## Remaining qualification

The new verified loader/artifact/image composition, independent key provisioning,
fixed operator file allowlist and authenticated CP read transport remain open.
Portal must authenticate this channel and bind observations to current run/slot
custody, preserve the last committed item prefix across restart, and commit
item-only transitions without inventing rolls. Native journal migration, new
launch custody, real native invocation, two-browser gameplay and save/resume
still require actual acceptance. Every profile qualification flag remains false.
