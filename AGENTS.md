# Project instructions

- Respond in Russian by default. Code, identifiers, comments and docstrings must be in English.
- Read README.md, PROTOCOL.md and RFC-AUDIT.md before changing transport behavior.
- Preserve the independent SDK: production packages must not import miray.
- Reuse the pinned rityak forks; keep upstream module import paths and explicit published replaces.
- Validate changes with `go test ./...` and `go vet ./...`; run `go test -race ./...` on Linux for lifecycle/concurrency changes. Independent-peer tests live in the separate `interop` module.
- The optional `mirayintegration` module requires the sibling core checkout described in its README. Do not substitute a global core configuration for session-local routes.
- Keep secrets, generated binaries, profiles and local configuration out of Git.
