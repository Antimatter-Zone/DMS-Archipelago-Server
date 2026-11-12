# Fresh Yacht publication runtime — source candidate

This is a separate, inactive profile: `public-yacht-publication-fresh-v1`.
It leaves the accepted Yacht action profile, its image and all historical
runtime sources unchanged. Source checks do not enroll a server, image,
publisher principal, key issuer, current deployment or physical-capacity permit.
The profile remains fresh-only; it cannot restart, restore, migrate or adopt an
existing owner lock, journal, native save, ACK or pending file.

`build.py` defaults to checking captured source only. Its foundation binds 38
historical files to exact raw SHA-256 and Git blob identities at Server
`80a423786d9efbce549a615bb1c297e9a1c2fd54`. The accepted action builder is executed
from those captured bytes and can read only that immutable inventory. The new
runtime inventory has exactly 22 files, including the unchanged publication
kernel, composition, action helper, frame policy, effects and observation code.
Notices, engine inventory, dependencies and source-transfer provenance remain
included. No key material or test modules enter the runtime inventory.

Explicit `--prepare --cache <directory> --output <new-external-directory>` is
offline and requires clean, committed, exact captured source. It creates a
build context, not an image. No automatic download, engine import, package
installation, image build, publication or deployment occurs in the default
source-check path. The pinned Docker recipe installs only admitted cached
wheels with networking disabled and uses UID/GID 65532.

The private bootstrap configuration has schema
`amz.ap.public-beta.yacht-publication-configuration.v1`, the new profile and
execution-profile hash, the existing exact action fields, and one additional
`publicationScopeSha256`. A future protected operator must supply that pin
independently after admitting the scope, resource and exact source/image tuple.
It must never be derived from an untrusted file or accepted as a room-editable
option. The scope file provides custody/integrity, not current authorization.
There is no enrollment/issuance API or production caller in this slice.

The runtime requires exactly five preexisting private files: runtime config,
Yacht keys, seed, publication scope and publication lock. Minimal bounded
bootstrap reads validate the protected hashes before any native owner is
created. The captured composition opens the existing fixed lock before the
first native budget audit/owner construction. Under that same genuine lock,
the loader repeats all private reads, compares the original bytes, verifies
the scope's identity/artifact/profile/source binding and checks the fresh
directory before initializing the first journal. A mismatch preserves owner
evidence and fails; it never clears or repairs a directory.

All native classes come from one isolated, captured nine-module namespace.
The loader uses only those fixed genuine component references; it does not
re-import a second `NativeFiles` through global `sys.modules`. The composition
keeps the original native RLock and acquires the shared publication flock only
inside synchronous filesystem transactions. Loader directory scans, key/seed
rereads, save-path prechecks, effects pending scans, effects old-read/write and
observation control scan/read have explicit guards. Engine handlers, native
snapshot serialization/get_save, observation parsing, and async drain run
outside the publication flock. Actual save and journal writers independently
cover the complete audit/plan/old-read/stage/fsync/replace/readback span. Nested
spans reuse their original local five-second ceiling; native command/MAC
deadlines are never renewed by coordination.

The kernel accounts for the complete fixed directory, including scope/lock,
old/new replacement overlap, the full 384 KiB external-control reservation,
512 KiB final-save headroom and 256 KiB metadata within 3 MiB. Unknown pending
files, permissions, links, expired custody or uncertain IO permanently hold the
owner. Cleanup does not retry inaccessible numeric FDs, remove uncertain
evidence, claim durable native save or release capacity.

Existing Panel write-then-chmod does not honor this lock and remains unsafe for
this profile. A separately enrolled restricted publisher transport and atomic
producer are still missing. No SSH/root credential is copied into a service.
Native key bootstrap, protected issuer, provider placement, encrypted capsule
quota, image qualification, browser gameplay, sleep/resume and public cutover
remain separate closed gates. The image recipe and source artifact must not be
treated as an approved runnable release.

Tests use isolated synthetic roots/identities with actual captured Linux
FD/flock/writer implementations; they do not claim UID 65532/provider or native
game qualification. The new Python suite explicitly runs the fixed new Node
launcher suite as a bounded subprocess. That subprocess is distinct from the
historical workflow's standalone Node group; the workflow itself is unchanged.
