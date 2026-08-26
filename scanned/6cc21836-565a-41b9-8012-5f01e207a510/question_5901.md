# Q5901: repoSync.SetupGitSSH — token persist after fail under password file

## Question
Does SetupGitSSH()'s `$GIT_SSH_COMMAND` string building, SetupCookieFile(), and the redaction helpers redactURL()/logSafeFlags() stay safe when an attacker makes the sync fail after the token is stored in the helper cache in `--password-file`, re-read on every sync for rotation — or can the token remains cached and usable for the full hour even though the operator's rotation assumed otherwise, violating “cached credentials do not outlive their issuing token” and producing extended validity window for a compromised token?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupGitSSH / SetupCookieFile / redactURL / logSafeFlags`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Makes the sync fail after the token is stored in the helper cache. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the token remains cached and usable for the full hour even though the operator's rotation assumed otherwise
- Invariant to test: cached credentials do not outlive their issuing token
- Expected Immunefi impact: extended validity window for a compromised token (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
