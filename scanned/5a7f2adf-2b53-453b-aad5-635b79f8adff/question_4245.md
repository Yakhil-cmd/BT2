# Q4245: repoSync.SetupGitSSH — stdin credential timing under http basic

## Question
Can an unprivileged attacker who makes `git credential approve` slow or fail while the blob is on stdin, under HTTPS auth with `--username` and `$GITSYNC_PASSWORD`, reach a state where — in SetupGitSSH()'s `$GIT_SSH_COMMAND` string building, SetupCookieFile(), and the redaction helpers redactURL()/logSafeFlags() — the error string returned by runWithStdin() embeds command output that can contain the credential context, and it is logged, breaking the invariant that credential material never appears in error strings and yielding credential disclosure via error reporting?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupGitSSH / SetupCookieFile / redactURL / logSafeFlags`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Makes `git credential approve` slow or fail while the blob is on stdin. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the error string returned by runWithStdin() embeds command output that can contain the credential context, and it is logged
- Invariant to test: credential material never appears in error strings
- Expected Immunefi impact: credential disclosure via error reporting (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
