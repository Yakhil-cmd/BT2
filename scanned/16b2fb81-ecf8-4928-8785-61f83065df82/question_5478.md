# Q5478: repoSync.StoreCredentials — askpass every sync amplify under verbose

## Question
Can an unprivileged attacker who stalls or fails the fetch so refreshCreds() (and the askpass call) runs on every retry, under an elevated `--verbose` level used for debugging in production, reach a state where — in StoreCredentials(): the `url=/username=/password=` blob piped into `git credential approve` — the askpass endpoint is hammered, and metricAskpassCount error paths mask the loop, breaking the invariant that credential refresh is rate-limited relative to failures and yielding denial of service against the operator's auth endpoint?

## Target
- File/function: [main.go](main.go) — `repoSync.StoreCredentials`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Stalls or fails the fetch so refreshCreds() (and the askpass call) runs on every retry. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the askpass endpoint is hammered, and metricAskpassCount error paths mask the loop
- Invariant to test: credential refresh is rate-limited relative to failures
- Expected Immunefi impact: denial of service against the operator's auth endpoint (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
