# Q4488: repoSync.RefreshGitHubAppToken — stdin credential timing under error file

## Question
Does RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage stay safe when an attacker makes `git credential approve` slow or fail while the blob is on stdin in `--error-file` inside --root, readable by the consumer — or can the error string returned by runWithStdin() embeds command output that can contain the credential context, and it is logged, violating “credential material never appears in error strings” and producing credential disclosure via error reporting?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Makes `git credential approve` slow or fail while the blob is on stdin. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the error string returned by runWithStdin() embeds command output that can contain the credential context, and it is logged
- Invariant to test: credential material never appears in error strings
- Expected Immunefi impact: credential disclosure via error reporting (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
