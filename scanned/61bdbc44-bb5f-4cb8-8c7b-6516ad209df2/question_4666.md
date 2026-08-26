# Q4666: repoSync.SetupDefaultGitConfigs — submodule gitmodules crlf under ssh auth

## Question
Starting from SSH auth via `--ssh-key-file` with the default `--ssh-known-hosts=false`, can an attacker who commits `.gitmodules` with CRLF, embedded newlines, or duplicate keys in section names drive the global git config git-sync installs before any submodule work (credential.helper cache, core.askPass true) to a state where the parsed submodule config differs from what review of the file suggests, hiding a malicious url or path, defeating “the effective submodule config equals the reviewable file content” and causing unauthorized content published / command execution hidden from review?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with CRLF, embedded newlines, or duplicate keys in section names. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the parsed submodule config differs from what review of the file suggests, hiding a malicious url or path
- Invariant to test: the effective submodule config equals the reviewable file content
- Expected Immunefi impact: unauthorized content published / command execution hidden from review (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
