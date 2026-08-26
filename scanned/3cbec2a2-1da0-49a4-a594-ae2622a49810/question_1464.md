# Q1464: repoSync.RefreshGitHubAppToken — askpass error to errorfile under ssh default

## Question
Does RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage stay safe when an attacker forces askpass failures whose error text carries the request URL and credentials in SSH auth with the default `--ssh-known-hosts=false` — or can logging.Error() serialises them into --error-file inside --root, readable by the consumer container, violating “secrets never reach the error file” and producing credential disclosure to the co-tenant workload?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Forces askpass failures whose error text carries the request URL and credentials. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: logging.Error() serialises them into --error-file inside --root, readable by the consumer container
- Invariant to test: secrets never reach the error file
- Expected Immunefi impact: credential disclosure to the co-tenant workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
