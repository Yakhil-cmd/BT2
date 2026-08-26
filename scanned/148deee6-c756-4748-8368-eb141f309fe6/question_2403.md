# Q2403: touch — errorfile symlink under error file

## Question
Can an unprivileged attacker who plants a symlink at the --error-file path (repo content, or a co-tenant on the shared volume), under `--error-file` inside --root, read by the consumer as a health signal, reach a state where — in touch()'s MkdirAll+Chtimes+Create, addUser()'s append to /etc/passwd, and sleepForever()'s terminal state — writeContent()'s rename-into-place writes error JSON through it, or DeleteErrorFile() removes the symlink target, breaking the invariant that error-file writes never follow attacker-controlled links and yielding arbitrary file overwrite/deletion outside --root?

## Target
- File/function: [main.go](main.go) — `touch / addUser / sleepForever`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Plants a symlink at the --error-file path (repo content, or a co-tenant on the shared volume). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: writeContent()'s rename-into-place writes error JSON through it, or DeleteErrorFile() removes the symlink target
- Invariant to test: error-file writes never follow attacker-controlled links
- Expected Immunefi impact: arbitrary file overwrite/deletion outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
