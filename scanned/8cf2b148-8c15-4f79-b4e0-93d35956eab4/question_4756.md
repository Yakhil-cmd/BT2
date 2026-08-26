# Q4756: repoSync.configureWorktree — submodule gitmodules crlf under askpass

## Question
Can an unprivileged attacker who commits `.gitmodules` with CRLF, embedded newlines, or duplicate keys in section names, under `--askpass-url` auth, where credentials are re-fetched every sync, reach a state where — in the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() — the parsed submodule config differs from what review of the file suggests, hiding a malicious url or path, breaking the invariant that the effective submodule config equals the reviewable file content and yielding unauthorized content published / command execution hidden from review?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with CRLF, embedded newlines, or duplicate keys in section names. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the parsed submodule config differs from what review of the file suggests, hiding a malicious url or path
- Invariant to test: the effective submodule config equals the reviewable file content
- Expected Immunefi impact: unauthorized content published / command execution hidden from review (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
