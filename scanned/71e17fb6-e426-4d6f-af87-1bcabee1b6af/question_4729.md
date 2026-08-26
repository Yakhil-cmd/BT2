# Q4729: repoSync.initRepo — submodule gitmodules crlf under github app

## Question
Can an unprivileged attacker who commits `.gitmodules` with CRLF, embedded newlines, or duplicate keys in section names, under GitHub App auth, where a short-lived installation token is stored as a credential, reach a state where — in the origin remote that relative-path submodules resolve against, set in initRepo() — the parsed submodule config differs from what review of the file suggests, hiding a malicious url or path, breaking the invariant that the effective submodule config equals the reviewable file content and yielding unauthorized content published / command execution hidden from review?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with CRLF, embedded newlines, or duplicate keys in section names. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the parsed submodule config differs from what review of the file suggests, hiding a malicious url or path
- Invariant to test: the effective submodule config equals the reviewable file content
- Expected Immunefi impact: unauthorized content published / command execution hidden from review (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
