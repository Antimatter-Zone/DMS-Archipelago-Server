# AMZ dedicated lobby runtime

This directory owns the headless MultiServer overlay formerly reviewed in Portal commit `63ec86cfb7845de67908a11291d015568bd477aa`. `source-provenance.v1.json` records the original inputs and the ordered ownership-comment patch. The upstream WebHost, root Dockerfile and later fork world changes remain intact.

Native startup/checkpoint acceptance passed for exact runtime source `f76abdbcc9a432f891a8500694e0621ae0a3ae3a`, including verified cleanup. The [sanitized acceptance record](acceptance/native-startup-f76abdbc.md) binds the source, local image, external runtime artifact and immutable generated receipt. Game qualification and deployment retain their separate gates.

The runtime uses Archipelago 0.6.8, commit `54803be064fc7e80c4628777ed0b46a9390f255f`. Its inventoried public source archive and eight binary wheels are hash verified before extraction. The six subsequent fork world differences are explicitly excluded from this pinned engine and retained in source. Changing that boundary requires a new reviewed pack and qualification.

The native eager-world loader exists only to collect hint exclusions. The second explicit overlay patch replaces that loader with `world-hints.v1.json`: identical empty defaults plus ALTTP's Triforce and CVCotM's Battle Arena exclusions, checked against every declaration in the pinned inventory without executing worlds. Dynamic, inherited or unrecognized overrides fail verification. Its exact metadata hash is bound in the runtime source/artifact. Unknown packs and AMZ world packs refuse startup until separately approved metadata and qualification exist; no custom world silently receives an assumed empty default. The isolated generation worker remains authoritative for executable worlds and settings.

The pinned native host-settings loader can also import every world while creating a missing host.yaml. The third explicit patch initializes the native `Settings(None)` cache with GUI/autosave disabled before importing MultiServer. Only native core defaults, fixed launcher arguments and reviewed embedded room rules apply. Mutable host settings are not an additional operational configuration source. This is a source-reviewed prevention measure; it is not evidence of the cause of the earlier failed native smoke.

Run source checks without importing engine code:

```text
python -B -m unittest discover -s amz-runtime/tests -p test_*.py
node --test amz-runtime/tests/redaction.test.mjs
python -B amz-runtime/build.py
```

From a clean committed checkout, `python -B amz-runtime/build.py --prepare` creates a new ignored context under `amz-runtime/.build/context-<commit>`. The download phase executes no engine or wheel code. The Dockerfile installs only the supplied wheel hashes with networking disabled. Runtime has no package installation, source update, remote shell or file service. Use the prepared context, never the repository root, to build the headless image.

`server-runtime.v1.json` is the versioned external `amz.ap.server-runtime.v1` input for Portal. Its SHA-256, exact Server commit, engine/pack, overlay inputs, immutable bases, requirements and provenance must match the protected signed operator policy before Member allocation or power actions. The artifact is source evidence; it is not an image signature, game qualification or deployment approval. Portal does not import files from this checkout.

Qualification remains open: image/egg signatures, redistribution/notice review, resource limits, standard AP client and real Paint/Yacht Dice browser connectivity, original-seed checkpoint load, DMS/Wings WebSocket routing and off-node encrypted recovery all require their own receipts. No image is published and no lobby is provisioned by these source checks. Keep the legacy deployment and Portal overlay until replacement coverage and rollback have been verified.

The first actual local image candidate (`b69bea07`) built successfully but its synthetic native smoke exited before a running observation. Its harness cleaned all owned containers and private inputs. The cause was not captured; do not attribute that observed failure to host settings. The current harness retains only bounded structured stage/exception diagnostics and output hashes on future failures, before the same exact cleanup. That earlier candidate did not establish native acceptance.

The subsequent `f05e4df8` image identified an engine verification failure before native imports. A read-only inventory probe found one mismatch in `worlds/ladx/LinksAwakeningClient.py`: repeated CR bytes made newline normalization non-idempotent. Preparation now verifies the normalized digest but preserves the original pinned archive bytes, so runtime verification normalizes exactly once. Every inventory entry remains checked; no source file or digest check is skipped. The repeated-CR regression covers this observed failure and was included in the accepted candidate.

Candidate `bde2fe5f` then passed the native startup, client check, checkpoint restoration, credential rotation and tampered-save assertions. Its overall harness still failed: a case-sensitive Docker error check prevented final private-fixture cleanup after all three owned containers had been removed. That premature pass receipt was marked incomplete and its original bytes retained; exact owned destroy events and healthy inventory proved cleanup before the fixture was removed. The current harness persists created IDs and terminal removal acknowledgments, checks exact name/ID inventories, preserves unknown or foreign resources, and publishes a pass only after verified cleanup. The clean `f76abdbc` repeat passed with that complete cleanup boundary.
