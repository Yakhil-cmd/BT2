# Q0774: Logger.Error — maxfail crashloop under error file

## Question
Does the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success stay safe when an attacker produces deterministic sync failures under `--max-failures` in `--error-file` inside --root, read by the consumer as a health signal — or can the container exits and CrashLoopBackOff stops all updates while the last-published data stays live, violating “repeated failure degrades gracefully rather than terminating the sidecar” and producing denial of updates for the consuming workload?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Produces deterministic sync failures under `--max-failures`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the container exits and CrashLoopBackOff stops all updates while the last-published data stays live
- Invariant to test: repeated failure degrades gracefully rather than terminating the sidecar
- Expected Immunefi impact: denial of updates for the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
