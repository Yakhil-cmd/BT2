# Q0852: repoSync.RefreshGitHubAppToken — askpass response injection under ssh known hosts

## Question
Under SSH auth with `--ssh-known-hosts` and a mounted known-hosts file, an attacker controls or influences the askpass response body (attacker-run endpoint reached via redirect, or response reflection). In RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage, can that mean the naive newline/`=` split lets an injected `password=` line or embedded newline overwrite the real credential or inject extra credential fields, so that the invariant “the askpass response is parsed as a strict, complete credential record” no longer holds and the outcome is credential substitution: git-sync authenticates to, or leaks to, an attacker-chosen target?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Controls or influences the askpass response body (attacker-run endpoint reached via redirect, or response reflection). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the naive newline/`=` split lets an injected `password=` line or embedded newline overwrite the real credential or inject extra credential fields
- Invariant to test: the askpass response is parsed as a strict, complete credential record
- Expected Immunefi impact: credential substitution: git-sync authenticates to, or leaks to, an attacker-chosen target (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
