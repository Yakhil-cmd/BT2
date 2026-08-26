# Q2067: repoSync.CallAskPassURL — github token in worktree under github app

## Question
Does CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response stay safe when an attacker arranges any path where the credential blob or token is written under --root rather than into the helper in GitHub App auth with `--github-app-*` flags — or can the token lands on the shared volume, violating “tokens exist only in memory and in the credential helper” and producing GitHub App token disclosure to the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Arranges any path where the credential blob or token is written under --root rather than into the helper. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the token lands on the shared volume
- Invariant to test: tokens exist only in memory and in the credential helper
- Expected Immunefi impact: GitHub App token disclosure to the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
