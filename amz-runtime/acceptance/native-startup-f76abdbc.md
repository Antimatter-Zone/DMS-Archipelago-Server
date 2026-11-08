# Native startup acceptance — 2026-11-08

The isolated headless server passed its complete native protocol/checkpoint acceptance, including verified cleanup, for the exact runtime source below. The harness and its outer guardian both exited with code 0.

| Binding | Exact value |
| --- | --- |
| Server runtime source | `f76abdbcc9a432f891a8500694e0621ae0a3ae3a` |
| Engine | Archipelago 0.6.8, `54803be064fc7e80c4628777ed0b46a9390f255f` |
| World inventory SHA-256 | `ea87c2f934bb559c64deeb76cf61253fdbb0d12b975de02929e18d97d508f54f` |
| External runtime artifact SHA-256 | `70fa51002ad028979a24762fd14a3d1a26c4646651b4c2c068d5f65fa4234aa6` |
| Native harness SHA-256 | `3dc621903a04b6aaa086b2d3f6b94cfe5d0bd5faf610cee6a465367b78594538` |
| Local candidate image ID | `sha256:2224ba50241295ffac5639f428a5996e58dc8cf811c3af40a751b463ec06e3c6` |
| Immutable generated receipt SHA-256 | `4df93a994a6f8a78daf9938561f2356450cfe8f7b5da20d5cbd78eb0a4cc7df3` |

The generated receipt remains unchanged at `amz-runtime/.build/native-acceptance-f76abdbcc9a432f891a8500694e0621ae0a3ae3a.json`. It is an external acceptance artifact, excluded from source. This document contains its sanitized bindings and result; engine files, wheels, binaries, configuration, passwords and private game data are not included.

The actual checks covered:

- Startup after verifying all 3,539 engine inventory entries.
- A standard AP protocol connection and location check against a synthetic APQuest-labeled multidata fixture.
- Native checkpoint creation, stopped-process restoration and retained checked-location progress with the original seed hash.
- Fresh credential epoch: old password rejected, replacement password accepted.
- Rejection of a modified checkpoint before a fresh running observation; stale telemetry did not count as startup proof.
- Actual Docker limits: 512 MiB memory, matching memory/swap ceiling, one CPU, 128 PIDs, nonroot user, read-only root filesystem, dropped capabilities and no-new-privileges.
- Network isolation with no published host ports.
- Three exact created container IDs with successful terminal removal acknowledgments, empty exact name/ID inventories and removal of the private fixture before pass publication. Independent post-run checks found zero owned containers or remaining private fixtures.

The source corrections preserve upstream archive bytes after one-time digest normalization and initialize the pinned native core-settings cache. The harness now retains bounded diagnostics on failure and refuses to publish a pass before cleanup is verified. Source checks passed: 15 Python cases plus the streaming-redaction test.

This result qualifies the isolated protocol/checkpoint startup path. **Qualified games: 0.** Playable world generation, actual game/browser clients, all 84 game records, DMS/Wings routing, signed image/egg publication, Wrapper composition, independent off-node restore and live provisioning retain their separate gates. The candidate image remains local; no live server or deployment was changed.

The validated executable source is the exact `f76abdbc` commit above. Later documentation-only commits record this evidence without changing that runtime identity or producing another accepted image.
