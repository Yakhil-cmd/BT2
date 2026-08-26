# Q5388: repoSync.RefreshGitHubAppToken — askpass every sync amplify under ssh known hosts

## Question
Starting from SSH auth with `--ssh-known-hosts` and a mounted known-hosts file, can an attacker who stalls or fails the fetch so refreshCreds() (and the askpass call) runs on every retry drive RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage to a state where the askpass endpoint is hammered, and metricAskpassCount error paths mask the loop, defeating “credential refresh is rate-limited relative to failures” and causing denial of service against the operator's auth endpoint?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Stalls or fails the fetch so refreshCreds() (and the askpass call) runs on every retry. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the askpass endpoint is hammered, and metricAskpassCount error paths mask the loop
- Invariant to test: credential refresh is rate-limited relative to failures
- Expected Immunefi impact: denial of service against the operator's auth endpoint (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
