# Current-provider bootstrap source

This is a separate fresh-only production-capable **source** package. It neither
enrolls an issuer/provider nor authorizes a Public launch. The accepted synthetic
`public-beta-yacht-bootstrap` package and all 22 native parent files stay intact.
The parent remains image `sha256:160a05753a026d3d8cfbcafa34d45a9d93f2b658ee0694f41d4f1c9df176ee12`,
artifact `7c65cc7984339622d1c515cdc7648af8220c3ade26a076292cc16fbcf3b2411c`,
profile `45d0e5de9dd8aade8197b2e66a36d5b6d1bfcf9e15f713c639c676b6b1978c1e`.
No historical image/profile is silently readmitted.

## Installed owner and real launch input

Hosting/Portal owns `/opt/dms/public-provider-owner/` with a separately enrolled
`/etc/dms/public-provider-owner.json`. It must capture this Server package and
actual Python tool before launching exactly:

```
<pinned-python> -I /opt/dms/public-provider-owner/server/production-bootstrap/publisher.py --server-uuid <original Panel UUID>
```

The publisher requires actual Linux Python3.12, UID/GID65532, empty kernel
supplementary groups, zero capability sets and NoNewPrivs1. FD3 is an inherited
duplex Unix socket whose actual creator peer is its retained root parent. The
owner independently checks actual child PID/start time, source/tool/FD identity
and target before sending any authorization. A request object, signed file,
room DTO, retained material or source-only driver cannot create that channel.
The publisher has no provider client, signer key, arbitrary path/command selector
or environment credentials.

The owner must durably record intent and validate the actual current complete
provider/physical namespace and permit, exact new full container ID/image ID,
volume and mount, actual native/boot root identities, actual normal Node and
worker identities/challenge, release/source/artifact tuple and original private
operator admission. It repeats these observations after the five-file readback
before signing, and before its final acknowledgment. Existing incomplete
all-namespace observation or unconditional node-permit refusal remains a closed
prerequisite; this source does not override either.

FD4..8 are bounded regular O_RDONLY private data descriptors, owned65532:65532,
mode0400 and nlink0/1, in the profile's five-file order. FD9/10 are the actual
O_RDONLY nofollow native/boot directory handles opened by the root owner from
its retained admitted Public namespace. The child verifies their actual kernel
proc-FD paths/identities and performs only FD-relative IO; it does not claim it
can traverse root0700 ancestors. The parent verifies full named ancestry and
same held directories at each exchange. The five data inputs contain:

1. The exact native publication-lock packet.
2. `amz.ap.public-beta.publication-scope-input.v1`: the ordinary scope fields
   except `rootDevice/rootInode/lockDevice/lockInode/lockSha256`.
3. The ordinary native configuration except `publicationScopeSha256`.
4. The raw pinned seed.
5. The ordinary independent native observation/effects key packet.

The publisher derives the omitted scope coordinates from its actual held root
and new lock inode, then derives the config scope hash from those actual bytes.
There is no pre-creation inode assertion or self-pinned scope. Owner custody must
bind the initial native master/MAC values to the Portal's encrypted private
material store before launch; those values never enter the public seal, protocol
output, website, logs or a source job. The owner must also reject reuse with its
actual held issuer/provider key inventory. The native's genuine existing key
separation checks still apply at initialization.

## Fixed private protocol and windows

Each FD3 message is one uint32BE length followed by at most65536 canonical UTF8
JSON bytes. Its exact frame fields are `schema,direction,sequence,kind,body`.
Schema is `amz.ap.public-beta.production-bootstrap-publisher.v1`; directions are
`publisher-to-owner` and `owner-to-publisher`. Only these three exchanges exist:

| Seq | Request | Reply |
| --- | --- | --- |
| 0 | `prepare` | `prewrite-authorized` |
| 1 | `files-created` | `seal-authorized` |
| 2 | `published` | `published-accepted` |

`prepare` contains publisher nonce, actual PID/parent/start/UID/GID/FD3 inode,
original server UUID, actual challenge/roots, five input byte/hash rows, and its
original dates. Reply0 binds that exact body SHA/nonce and immutable operation
UUID. Request1 contains actual final five file metadata rows, challenge/scope
hashes and original request SHA. Reply1 binds its exact body SHA/nonce and the
canonical signed seal in base64. Request2 and reply2 are the same exact public
nonce/operation/seal/files/scope hash projection. No reply carries private keys.

The owner captures its original startup limit before spawning, capped by the
actual runtime challenge; it must cap every child date to that original window.
The publisher captures its own wall/monotonic30s budget before target/input IO,
then caps it to the challenge. The original prewrite acknowledgment shortens
**all remaining publisher work** to at most5s; the final signature does not renew
it. Runtime Node PID1 independently starts its original30s before image/input IO,
and Python caps itself to Node's original bound. The final provider receipt and
seal each last at most5s, and the seal cannot extend the provider receipt or
challenge. EOF/cancel/clock rollback/expiry/unknown close refuses; no reroll,
repair, deletion or retry adopts retained files.

## Independent public trust and seal

The protected builder accepts one independently pinned public-only definition:

```
{schema:'amz.ap.public-beta.production-bootstrap-trust.v1',
 issuer:{keyId:'amz.ap.public-beta.production-bootstrap-seal.v1',rootPublicKeyPem,rootSpkiSha256},
 provider:{keyId:'amz.ap.public-beta.yacht-provider-launch.v1',rootPublicKeyPem,rootSpkiSha256}}
```

Both are actual distinct Ed25519 SPKI roots. Default trust is unconfigured and
refuses startup. A `mode`, enrollment boolean or synthetic trust file cannot
enable this entrypoint. Node performs actual crypto verification for both keys.

The issuer envelope schema is `amz.ap.public-beta.production-bootstrap-envelope.v1`.
It has exactly `schema,body,signature`; signature is canonical base64 Ed25519
over `amz.ap.public-beta.production-bootstrap-seal.v1`, LF, canonical body.
The body has the historical seal fields plus `launch`, with its schema/purpose
changed to that production seal domain. `provider.attestation` is exactly
`current-provider-launch-v1`.

`launch` is a separate envelope `amz.ap.public-beta.yacht-provider-launch-envelope.v1`,
signed over `amz.ap.public-beta.yacht-provider-launch.v1`, LF, canonical body.
Its exact body fields are:

```
schema,operationId,provider,identitySha256,challengeSha256,process,nativeRoot,
bootstrapRoot,bootstrapArtifactSha256,native,filesSha256,publicationScopeSha256,
providerProfileSha256,placementDefinitionSha256,physicalPermitSha256,
nodeIdentitySha256,issuedAt,expiresAt
```

`provider` here has only `serverUuid,containerId,imageId,volumeId`. The verifier
joins every value to the issuer seal and actual challenge, including both root
inodes and the original full process tuple. The owner signature attests its real
current external observations; the container cannot establish them from its own
hostname or JSON. Both roots must be independently enrolled for those purposes.

The publisher uses held nofollow fixed roots under
`/srv/public-beta/wings/data/<serverUuid>/{.amz,.amz-bootstrap}`. It requires fresh
native space and only the actual challenge in BOOT, creates exactly five0600
files exclusively, fsyncs file+directory and rereads the same FD/named inode.
It never writes through Panel write/chmod. It then receives the owner's signed
seal and uses O_TMPFILE/O_RDWR (without O_EXCL), fsync/readback at nlink0 and
exclusive fixed proc-FD `linkat(...,AT_SYMLINK_FOLLOW)` to publish `seal.json` last.
There is no visible pending name, overwrite, rename or unsupported-kernel fallback.

After seal publication the worker may create native journals immediately. The
publisher continues to bind the five immutable input inodes/bytes and seal, but
does not claim a post-initialization empty/full namespace or Ready state. Its
terminal output follows independent once-only FD settlement and final original
window check; it explicitly grants no initialization or resource release.
The owner must observe genuine Ready/ACKs and settle its actual child/provider
resources separately. Any lost return/partial write/close uncertainty is retained.

## Source packaging and remaining acceptance

`build.py --prepare --output <new-external-directory> --public-trust <public-file> --expected-sha256 <raw-pin>`
captures actual committed source and tests. It emits Dockerfile, the bootstrap
runtime context and a separate issuer package/artifact. It does not build/pull,
sign, install, enroll or launch. Issuer code is not copied into the runtime image.
The parent image must be bound independently to its exact admitted full ID.

Tests are source/pure crypto and explicitly adapted owned-Linux filesystem
fixtures. They do not qualify the actual UID/peer deployment, signed production
issuer/provider roots, complete collector/node permit, encrypted initial custody,
normal image/provider transport, authorized gameplay, restore/resume or activation.
No production profile is registered by this change.
