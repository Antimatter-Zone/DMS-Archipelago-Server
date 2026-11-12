# Fixed private publication command — source only

`runtime/command.py` is an uninstalled one-shot program and Python processor.
It changes none of the existing 22 runtime/profile bytes. It starts no listener,
subprocess, SSH session, Docker operation or network connection. The accepted
local image remains unchanged and does not contain this new command.

The future restricted launcher must admit the command's exact source bytes and
provide an independently authorized server UUID and publication-scope SHA-256.
Those boot arguments convey custody/integrity only. This program does not prove
current operator/MFA approval, Panel/provider ownership, the running container,
the backend destination, capacity, a physical node permit or native enrollment.
No production launcher, Unix socket, forced-command principal, policy issuer or
target/dial-authority factory is installed or enrolled by this source.

## Actual invocation

The explicit, Linux-only invocation is:

```text
<pinned-python> -I -B <admitted-command.py> --once --server-uuid <protected-UUID> --scope-sha256 <protected-SHA256> --issued-at <original-ISO> --expires-at <original-ISO>
```

The principal must be UID/GID 65532. The server UUID and scope pin must come from
protected current-target custody, never a website body or retained backend URL.
There are no path, host, UID, key, executable or environment fallback arguments.
The sole sibling source `publication.py` is opened as a bounded, nonsymlink,
single-link regular file, captured from one FD with named/readback identity, and
matched to the fixed `f7cf9584…` SHA-256 before isolated execution. The accepted
kernel is used without edits. Its imports are fixed standard-library imports;
caller modules and approval callbacks cannot obtain the private source brand.

Stdin contains exactly one canonical UTF-8 JSON object, followed by EOF, at most
98,304 bytes. Whitespace, BOMs, duplicate keys, nonfinite numbers, multiple frames
and extra fields refuse. The original maximum-five-second wall/monotonic window
is captured **before** source, stdin or target IO. Kernel windows are capped by
that same retained monotonic deadline. IO, lock waits, response writing and
cancellation cannot renew it. An incomplete stdout frame or nonzero exit is an
unknown result, never a publication acknowledgement. Stdout is the private reply
channel; it must not be copied to application logs. A late output failure may
leave a partial private frame, which must be discarded. Error handling emits no
exception messages, raw error data or diagnostic copies of the private payload.

## Fixed ABI

The exact request keys are:

```json
{"schema":"amz.ap.public-beta.publication-command.v1","requestId":"<UUID>","identity":"<exact native identity object>","issuedAt":"<original ISO milliseconds Z>","expiresAt":"<original ISO milliseconds Z>","action":"publish or read","channel":"<fixed channel>","payload":null}
```

The example's `identity` placeholder is an object in a real request; the kernel
requires all 12 actual native identity fields. It must equal the independently
pinned scope, and both dates must equal the protected opening window exactly.

For `publish`, channels are only `gateway`, `yacht-observation` and
`yacht-effects`. `payload` is canonical padded base64 of at most 65,536 bytes of
canonical native control JSON. Its native operation/request/delivery UUID must
equal `requestId`; schema, identity, purpose and original dates must match. The
kernel's fixed pending-file reservation, nofollow FD custody, EX flock, fsync,
atomic rename, directory fsync and exact readback perform the actual publication.
Native validation and MAC checks remain authoritative. The command receives no
observation key, effects key, website token, DMS credential or signing key.

For `read`, `payload` must be null and only these channels exist:

| Channel | Fixed private leaf | Maximum |
| --- | --- | --- |
| `gateway-ack` | `public-gateway-ack.json` | 64 KiB |
| `yacht-observation-ack` | `public-yacht-observation-ack.json` | 512 KiB |
| `yacht-effects-ack` | `public-yacht-effects-ack.json` | 64 KiB |
| `status` | `public-runtime-status.json` | 16 KiB |

Reads take the same enrolled publication lock and perform complete workspace
audits plus same-FD/named inode/owner/mode/link/size checks before returning exact
bytes. A missing leaf returns `absent`; it is only an absent-now observation.
An ACK/status body is not interpreted as a grant, authenticated native result,
save, permanent fence, cleanup proof or capacity release. Existing operator
parsers must independently verify their own exact native correlation and MAC.

The canonical response schema is
`amz.ap.public-beta.publication-command-result.v1`. It binds the request ID, exact
request SHA-256, identity, original dates, action and channel. Publication results
are the fixed kernel metadata receipt. Read results contain `state`, canonical
base64 `payload`, `payloadSha256` and `bytes` (or null/null/zero if absent). The
whole response is at most 720,896 bytes and always says source-only, activation
false, qualification false, native acknowledgement false, native save durability
false and resource-release authority false. The local stdio channel has no
transport authentication; a future launcher must authenticate its own endpoint
and framing before trusting it. Hashes alone are not authentication.

## Factory and lifecycle

`capture_command_sources(kernelRaw)` requires the fixed raw kernel bytes before
compiling them. `open_host_command(sources, serverUuid, expectedScopeSha256,
issuedAt, expiresAt)` captures only the fixed host volume derived by the kernel,
one exact scope and one enrolled lock. It returns a private-branded exact-type
handle with `execute(rawRequest)`, `cancel()` and `close()`.

Every handle permits one attempt. It performs no automatic retry, journal
retirement, redispatch, file deletion or reconciliation. The protected future
caller must durably record its exact intent before invoking a mutator. A lost
acknowledgement, timeout or uncertain publication remains held in that caller's
journal even when the command process exits. Pending files and native journals
are retained. Restarting the command is not a way to settle an unknown operation.

Close attempts each owned handle once. Unknown internal FD/close outcomes require
process exit; numeric descriptors are never guessed or retried. Closing a local
handle does not remove the scope/lock, release provider resources or settle a
capacity charge. No public method exposes a generic read, write or shell action.

Source tests reuse the actual kernel in separately compiled, counted fixed-root
and UID/GID fixtures. Linux cases exercise real owned files, descriptors, flock,
fsync/replace, child-process framing, partial-read races and uncertain readback.
Fixture brands cannot cross to unchanged modules. Synthetic controls deliberately
contain no genuine native MAC. These tests do not qualify the production
principal, provider target, command issuer, remote transport, native image,
encrypted quota, gameplay or public hosting.
