# Q4738: repoSync.SetupDefaultGitConfigs — submodule gitmodules crlf under github app

## Question
Under GitHub App auth, where a short-lived installation token is stored as a credential, an attacker commits `.gitmodules` with CRLF, embedded newlines, or duplicate keys in section names. In the global git config git-sync installs before any submodule work (credential.helper cache, core.askPass true), can that mean the parsed submodule config differs from what review of the file suggests, hiding a malicious url or path, so that the invariant “the effective submodule config equals the reviewable file content” no longer holds and the outcome is unauthorized content published / command execution hidden from review?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with CRLF, embedded newlines, or duplicate keys in section names. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the parsed submodule config differs from what review of the file suggests, hiding a malicious url or path
- Invariant to test: the effective submodule config equals the reviewable file content
- Expected Immunefi impact: unauthorized content published / command execution hidden from review (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
