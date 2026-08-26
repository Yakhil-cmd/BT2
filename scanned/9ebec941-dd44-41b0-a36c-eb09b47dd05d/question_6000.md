# Q6000: repoSync.RefreshGitHubAppToken — token persist after fail under ssh default

## Question
Can an unprivileged attacker who makes the sync fail after the token is stored in the helper cache, under SSH auth with the default `--ssh-known-hosts=false`, reach a state where — in RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage — the token remains cached and usable for the full hour even though the operator's rotation assumed otherwise, breaking the invariant that cached credentials do not outlive their issuing token and yielding extended validity window for a compromised token?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Makes the sync fail after the token is stored in the helper cache. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the token remains cached and usable for the full hour even though the operator's rotation assumed otherwise
- Invariant to test: cached credentials do not outlive their issuing token
- Expected Immunefi impact: extended validity window for a compromised token (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
