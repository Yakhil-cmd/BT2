# Q3912: repoSync.RefreshGitHubAppToken — md5 cred log under http basic

## Question
Does RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage stay safe when an attacker gets verbosity raised or an error path that includes the V(9) credential md5 line in HTTPS auth with `--username` and `$GITSYNC_PASSWORD` — or can md5 of username and password land in logs, enabling offline cracking of weak credentials, violating “no derivative of a credential is logged” and producing credential disclosure via log-derived hashes?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Gets verbosity raised or an error path that includes the V(9) credential md5 line. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: md5 of username and password land in logs, enabling offline cracking of weak credentials
- Invariant to test: no derivative of a credential is logged
- Expected Immunefi impact: credential disclosure via log-derived hashes (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
