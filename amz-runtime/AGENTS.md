# Dedicated AMZ lobby runtime

This directory owns the headless MultiServer runtime and versioned source artifact. The upstream WebHost, worlds and historical Dockerfile remain intact. Never start a lobby, publish an image, alter DMS/Panel resources or retire a legacy deployment as a source-test side effect.

Use only Archipelago0.6.8 commit54803be064fc7e80c4628777ed0b46a9390f255f and the pinned inventory. Later fork differences are preserved and recorded explicitly, not silently installed. Build contexts accept only regular bounded hash-verified archive entries and pinned binary wheels. Runtime performs no download, package install, git update, arbitrary command or remote administration.

The Portal consumes the generated versioned artifact through its signed release-policy hash. It must not import sibling checkout files. Preserve all engine/dependency/source notices. Actual native/browser clients, checkpoint loading, resource limits, image/egg signature and DMS/Wings routing remain distinct qualification gates.
