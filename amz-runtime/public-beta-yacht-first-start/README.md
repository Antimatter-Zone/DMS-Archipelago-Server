# Yacht first-start profile v1

This additive source profile is based on Server commit `825e88b9c47c9632fd8179d922498bffcea780cd`. The historical production-bootstrap package and all 22 native-publication files remain unchanged. The new layer has no published image digest, installed CP activation sender, enrolled launch key, or physical/native qualification. Preparing its source context does not build or register an image.

The historical bootstrap could acknowledge journal initialization before the native listener existed, and the native publication loader then called `mark_ready` immediately after binding the listener. The new loader instead keeps the actual `NativeBarrier.ready` flag false while it verifies the actual loaded Yacht context, listener, seed, roster, upstream ABI, initial item inventory and absence of game clients/preparations. It never uses an idle gate, fakes a ready flag, or accepts browser observations.

## Immutable source and inputs

The build helper reads its nine source files and two tests from one committed Git tree. It also verifies the seven historical production-bootstrap files against both the accepted parent commit and that tree. It uses the existing pinned owner-repository Git reader; there is no sibling-checkout import. The native image/artifact/profile/source and full native 22-file inventory remain independently pinned. The versioned `native_loader.py` overlay retains the actual native input validation, composition, engine, packet policy, checkpoint and ordinary gameplay control implementations.

The generated runtime closure is `bootstrap.py`, `first_start.py`, `launcher.mjs`, `native_loader.py`, `runtime-profile.json`, `trust-profile.json`, plus its artifact. The separate issuer output contains only the fixed publisher source and its versioned artifact. The issuer is not copied into the runtime image. The protected builder must prove the exact parent image ID rather than trust an arbitrary supplied tag; the preparation receipt explicitly reports that this check and an actual image build have not occurred.

The five original private input schemas are retained. In particular `run.seedName` must be the actual native seed name, with its exact actor-to-slot roster, seed hash, configuration and build pins. The generation V2 metadata/real primary-custody path is a separate dependency; this profile never invents a seed name from a room ID or a DTO. Seed input remains limited to 512 KiB.

The public trust input has the closed schema `amz.ap.public-beta.yacht-first-start-trust.v1` and keys `issuer`, `provider`, and `launchCommand`. Each configured entry is `{keyId,rootPublicKeyPem,rootSpkiSha256}` and must contain only an Ed25519 public key. The first two existing purposes are unchanged. The dedicated third purpose is `amz.ap.public-beta.yacht-first-start-activation.v1`; it must use a different key. A null third entry permits no activation. The default generated trust has all three entries null and refuses normal bootstrap before opening a listener.

This public activation root must be enrolled through the future signed Portal deployment/release and protected image/bootstrap provenance, including the exact artifact/trust bytes and actual provider image/scope. It is never obtained from an activation packet. No CP private key is present in this image, in a publisher FD, or in the preparation output. The new root is a command-purpose trust pin, not a new deployment approval or MFA policy.

## Original clock and private channel

The normal PID1 launcher captures one original wall/monotonic 30-second startup deadline before private input capture or Python spawn. The Python worker receives that exact bound over its existing inherited pipe. Initialization no longer closes the channel or clears the timer. Listener startup, held observation, CP publication, activation verification, genuine journal readiness and the final acknowledgement all remain within that original deadline. Every control/response and signed activation also has an original lifetime of at most five seconds, capped by startup and the observed held-ready expiry. No packet, retry or phase renews either clock.

The inherited channel has exactly six worker exchanges, sequences 0 through 5: `challenge`, `verify-seal`, `initialized`, `held-ready`, `verify-activation`, and `activated`. Each exact canonical UTF-8 JSON frame has a four-byte big-endian length and a 32 KiB ceiling. Parent responses use the same sequence and fixed matching kind. A different/extra/incomplete message, pipe loss, cancellation, clock rollback or expiry stops the owned worker; bounded TERM/KILL settlement requires its actual close acknowledgement. An unknown close is reported as failure, without a resource-release claim.

The publisher entry is `/opt/dms/public-provider-owner/server/first-start-v1/publisher.py`. It retains the original UID 65532, root-owned inherited FD3 peer, read-only private inputs FD4–8, held native/boot directory FDs9–10, original seal-last writes and both independent issuer/provider signatures. Its channel is versioned `amz.ap.public-beta.yacht-first-start-publisher.v1`; it holds no signer key. A future installed owner adapter must consume the new issuer artifact and actual child/FD/native/provider custody. The historical publisher is not compatible with the new profile hash and is not relaxed.

## Held-ready observation

Only the dedicated `.amz-bootstrap/first-start-control.json` is read before readiness. Gameplay observation/control paths are unchanged, and cannot consume a leftover startup packet after activation. A request is an exact canonical object:

```
{schema,requestId,nonce,identitySha256,issuedAt,expiresAt,requestMac}
```

Its schema is `amz.ap.public-beta.yacht-first-start-observe.v1`. The key is derived from the actual captured independent observation key with HMAC-SHA256 and the fixed bytes `amz.ap.public-beta.yacht-first-start-key.v1`. Request/response MACs use their own schema, LF, then canonical object bytes excluding the MAC. This correlation authenticates the private observation channel; it does not authorize activation.

The loader-only `FirstStart` object is closed to ordinary construction. Its factory verifies the actual composition's private registry, captured sources, exact native file/barrier classes, actual verified native ABI/context and the bootstrap's real private channel/consumed seal brand. It retains fresh same-FD identities for all five sealed input files. Each observation rechecks them, the held boot directory, actual listener, upstream functions, decoded seed/roster/slot data, initial items, and the real barrier's zero/fresh state. No SQL rows, HTTP DTOs or callbacks substitute for these objects.

The private worker sends Node the full observed binding:

```
{identity,operationId,nativeInstance,configurationSha256,seedArtifactSha256,
 seedNameSha256,rosterSha256,browserBuildSha256,listener,native,provider,
 firstStart,publicationScopeSha256,startupExpiresAt}
```

`nativeInstance` is the original challenge's actual PID1/worker start ticks and worker PID. `native`, `provider`, configuration/seed/scope hashes and the first-start artifact/profile must match the independently verified seal. The listener must actually be bound at `0.0.0.0` and the configured port. The held-ready body additionally has its fixed schema, `listenerReady:true`, `admissionHeld:true`, `connectedClients:0`, and short dates. Node accepts this only through the live owned worker pipe. Its canonical SHA binds the response and the later activation.

The private ACK contains that SHA, the binding SHA, request/nonce, actual held facts and short dates plus a purpose-bound response MAC. It makes no ready, Play, save, provider release or Current Slot claim. The future CP consumer must compare the complete expected binding from its own retained launch and actual physical observations, rather than treat the SHA or MAC as a deployment authority.

The single installed producer publishes each control through the exact fixed `.first-start-control.json.pending` regular file and atomic rename, preserving the original deadline and previous input identity. The reader waits while that bounded pending name exists and never reads it as a completed packet. Other pending metadata still refuses sealed operation. The runtime publishes its ACK through its own exact pending name, with fsync and same-FD/named readback; no pending or foreign object is repaired or deleted by the reader.

## Activation after actual CP publication

The second control request has schema `amz.ap.public-beta.yacht-first-start-activate.v1` and exact fields `{schema,requestId,nonce,heldReadySha256,activation,issuedAt,expiresAt,requestMac}`. `activation` is:

```
{schema:"amz.ap.public-beta.yacht-first-start-activation-envelope.v1",
 body:{schema:"amz.ap.public-beta.yacht-first-start-activation.v1",
       requestId,nonce,heldReadySha256,binding,committedPublicationSha256,
       controlDefinitionSha256,releaseDefinitionSha256,issuedAt,expiresAt},
 signature}
```

The Ed25519 signature is over the fixed activation purpose, LF, and canonical body bytes. `binding` must exactly equal the actual worker's previously accepted full binding. The packet cannot select a key, purpose, endpoint, source or file. Wrong keys, purposes, context/native instance, seed/configuration/roster/image/source/profile/launch, replayed nonce, altered publication digest, or expired original windows refuse. The parent returns an activation acknowledgement only after its actual Node crypto verification; HMAC possession alone is insufficient.

**The future Portal SQL017 sender does not exist in this cohort.** It must own the restricted actual launch operation and independently read back its freshly committed `RUNNING` + `BOUND` room/runtime publication and roster before signing this command, within the same original launch deadline. The Server can verify that enrolled command key's exact assertion; it cannot query or create that CP commit. Current Slot must retain its existing actual `RUNNING` + `BOUND` requirement. There is no public endpoint, arbitrary shell/RPC, guessed live origin, fake production fixture or auto-activation sender here.

Only after Node's acknowledgement and another actual held-state/input/listener check does the single native loop call the genuine durable `NativeBarrier.mark_ready`. It then constructs the unchanged gameplay controls and acknowledges the actual activated journal over the original channel. Missing/expired activation leaves readiness false and drains/stops the native process; a failed transition or uncertain write never creates a successful ACK. This is fresh first-start only, with no restore, sleep/resume, migration or replacement adoption.

## Storage and qualification

The new profile reserves an explicit 80 KiB `.amz-bootstrap` workspace. The auditor allows exactly ten current/pending metadata names: the three historical metadata pairs plus the first-start control and ACK pairs. Current and pending sizes and actual allocated `st_blocks` are counted, plus a 4 KiB directory reserve. The fixed maxima reserve 69,632 bytes even when files are absent. Control payloads remain at most 4 KiB and ACK payloads at most 2 KiB; their allocation reservation is 4 KiB each. No sparse/absent file gives free credit. Future Portal/node admission must account for the new 80 KiB profile. The historical 64 KiB auditor and native 3 MiB policy remain unchanged.

Source tests cover actual Node Ed signatures/purpose/full-binding/original windows, canonical bounded frames, private-brand denials, real Linux nofollow/same-FD directory and block accounting, retained fsync failure evidence, and an actual native journal refusing readiness without its bound observer. They do not start an engine/listener or supply positive physical authority. The real signed deployment/image/issuer/provider/CP key enrollment, new installed owner adapter, native seed metadata, physical capacity, actual first-start connection fence/activation and real client acceptance remain unqualified.

Proposed source checks (Root owns execution):

```
node --test amz-runtime/public-beta/tests/yacht-first-start.test.mjs
python -m unittest discover -s amz-runtime/public-beta/tests -p test_yacht_first_start.py
```

The context builder requires these eleven paths to be committed before `--prepare`. Its only output action is an exclusive, bounded, fsynced context outside the repository. Existing upstream/AP engine and dependency notices remain in the pinned parent image and source inventory; no engine or dependency bytes are replaced by this layer.
