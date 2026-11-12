# Private control publication kernel candidate

This is an inactive, Linux-only source slice. It changes no existing loader,
image, Panel API, Wings API, or runtime profile. There is no CLI, transport,
bootstrap, enrollment issuer, deployment, or production caller. Every result
states `sourceOnly: true`, `activation: false`, and `qualification: false`.

`capture_window(issuedAt, expiresAt)` captures the remaining original wall and
monotonic deadline before filesystem IO. Its maximum interval is five seconds;
it cannot extend a payload deadline and cancellation can only shorten it.

`capture_runtime_scope(expectedEnrollmentSha256, window)` uses only
`/home/container/.amz`. `capture_host_scope(serverUuid, expectedEnrollmentSha256,
window)` derives only `/srv/public-beta/wings/data/<canonical server UUID>/.amz`.
Both capture real directory and enrollment descriptors. The enrollment is a
pre-existing, canonical, mode-0600, single-link file owned by UID/GID 65532. Its
independent expected hash is a protected bootstrap argument, never a public
request parameter and never derived from the file being admitted. Scope bytes
bind root/device/inode, run identity, exact server/container IDs, image and
source/profile/artifact references, and the existing publication-lock identity.
These references are custody/integrity pins only: the kernel does not verify a
running container, signatures, current deployment authorization, MFA, provider
ownership, physical capacity, or a node permit. That missing enrollment and
protected caller must remain closed. A copied JSON value cannot create a scope,
window, or lock brand.

`PublicationLock(scope, window)` opens the pre-enrolled
`public-control-publication.lock`; it never creates, replaces, or removes it.
It uses one held FD, a process-local reentrant exclusive mutex, and Linux
`flock(LOCK_EX | LOCK_NB)` with the original deadline. Nested calls do not
downgrade or release an outer lock. It is separate from the lifetime-held
`public-gateway-native.lock`.

`FixedControlPublisher(scope, lock, window).publish(kind, operationId, raw,
window)` accepts only `gateway`, `yacht-observation`, or `yacht-effects`.
The names, pending names, UID, and maximum 64-KiB canonical payload are fixed.
The outer schema, purpose, operation ID, identity, and original dates must
match. Native validation, including observation/effects MAC verification and
full command semantics, remains authoritative. The publisher receives no MAC,
signing, website, or DMS credential.

Under the same lock, publication audits the fixed workspace and charges the
entire current-plus-one-pending control maxima even if absent (384 KiB), plus
256 KiB metadata and every other actual bounded file, against 3 MiB. The new
scope and lock bytes count too. Any unknown or pending entry refuses the next
publication. It reserves this bound before opening its sole fixed temporary
file, writes exclusively at mode 0600, fsyncs, verifies the retained FD and
named bytes, atomically replaces the fixed final, fsyncs the directory, and
verifies complete final bytes and descriptor identity. No uncertain pending
or final is automatically deleted. An attempted write followed by error,
cancellation, expiry, or failed readback holds that scope; future protected
reconciliation is separate and is not implemented here. The metadata receipt
is neither a native ACK nor save, fence, replacement, or capacity-release proof.

A future profile must enroll this lock **before** initial native budget audit,
owner-lock creation, seed/save/status setup, and all control use. Every full
audit/read/write/pending/readback transaction must share it, with the native
RLock before publication flock and one reentrant lock instance per scope.
This source does not yet compose those paths. Ordinary Panel writes do not
cooperate and cannot be accepted as a fallback. The existing 51117 profile
cannot admit the new scope/lock files or safe publication through this module.

Source tests use a separately loaded module with narrowly counted fixed-root
and UID/GID substitutions into owned temporary directories. Their private
brands cannot cross to the unchanged module. Real Linux FD/flock/fsync/replace
tests are source evidence, not UID-65532, host, image, transport, enrollment,
native-delivery, quota-admission, or gameplay qualification. There are no
production IO, clock, platform, approval, or path callbacks.
