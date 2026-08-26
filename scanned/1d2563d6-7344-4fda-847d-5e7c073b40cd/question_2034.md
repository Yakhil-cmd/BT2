# Q2034: Logger.Error — touch mkdirall symlink under http metrics

## Question
Under `--http-metrics` enabled for Prometheus scraping, an attacker commits a symlink on the path components leading to --touch-file. In the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success, can that mean touch()'s MkdirAll/Create follows it and creates files outside --root, so that the invariant “readiness-file creation is confined to --root” no longer holds and the outcome is file creation outside --root on a co-mounted volume?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Commits a symlink on the path components leading to --touch-file. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: touch()'s MkdirAll/Create follows it and creates files outside --root
- Invariant to test: readiness-file creation is confined to --root
- Expected Immunefi impact: file creation outside --root on a co-mounted volume (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
