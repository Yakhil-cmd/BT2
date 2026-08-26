# Q3984: repoSync.RefreshGitHubAppToken — md5 cred log under askpass

## Question
Can an unprivileged attacker who gets verbosity raised or an error path that includes the V(9) credential md5 line, under `--askpass-url` auth, re-fetched every sync, reach a state where — in RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage — md5 of username and password land in logs, enabling offline cracking of weak credentials, breaking the invariant that no derivative of a credential is logged and yielding credential disclosure via log-derived hashes?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Gets verbosity raised or an error path that includes the V(9) credential md5 line. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: md5 of username and password land in logs, enabling offline cracking of weak credentials
- Invariant to test: no derivative of a credential is logged
- Expected Immunefi impact: credential disclosure via log-derived hashes (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
