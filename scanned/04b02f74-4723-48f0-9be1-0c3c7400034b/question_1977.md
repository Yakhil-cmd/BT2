# Q1977: repoSync.SetupGitSSH — github token in worktree under http basic

## Question
Under HTTPS auth with `--username` and `$GITSYNC_PASSWORD`, an attacker arranges any path where the credential blob or token is written under --root rather than into the helper. In SetupGitSSH()'s `$GIT_SSH_COMMAND` string building, SetupCookieFile(), and the redaction helpers redactURL()/logSafeFlags(), can that mean the token lands on the shared volume, so that the invariant “tokens exist only in memory and in the credential helper” no longer holds and the outcome is GitHub App token disclosure to the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupGitSSH / SetupCookieFile / redactURL / logSafeFlags`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Arranges any path where the credential blob or token is written under --root rather than into the helper. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the token lands on the shared volume
- Invariant to test: tokens exist only in memory and in the credential helper
- Expected Immunefi impact: GitHub App token disclosure to the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
