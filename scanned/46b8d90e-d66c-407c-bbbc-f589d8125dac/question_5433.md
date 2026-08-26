# Q5433: repoSync.SetupGitSSH — askpass every sync amplify under cookie file

## Question
Under `--cookie-file` enabled, an attacker stalls or fails the fetch so refreshCreds() (and the askpass call) runs on every retry. In SetupGitSSH()'s `$GIT_SSH_COMMAND` string building, SetupCookieFile(), and the redaction helpers redactURL()/logSafeFlags(), can that mean the askpass endpoint is hammered, and metricAskpassCount error paths mask the loop, so that the invariant “credential refresh is rate-limited relative to failures” no longer holds and the outcome is denial of service against the operator's auth endpoint?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupGitSSH / SetupCookieFile / redactURL / logSafeFlags`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Stalls or fails the fetch so refreshCreds() (and the askpass call) runs on every retry. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the askpass endpoint is hammered, and metricAskpassCount error paths mask the loop
- Invariant to test: credential refresh is rate-limited relative to failures
- Expected Immunefi impact: denial of service against the operator's auth endpoint (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
