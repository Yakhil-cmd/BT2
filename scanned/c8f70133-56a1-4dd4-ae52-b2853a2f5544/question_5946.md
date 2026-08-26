# Q5946: repoSync.StoreCredentials — token persist after fail under github app

## Question
Under GitHub App auth with `--github-app-*` flags, an attacker makes the sync fail after the token is stored in the helper cache. In StoreCredentials(): the `url=/username=/password=` blob piped into `git credential approve`, can that mean the token remains cached and usable for the full hour even though the operator's rotation assumed otherwise, so that the invariant “cached credentials do not outlive their issuing token” no longer holds and the outcome is extended validity window for a compromised token?

## Target
- File/function: [main.go](main.go) — `repoSync.StoreCredentials`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Makes the sync fail after the token is stored in the helper cache. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the token remains cached and usable for the full hour even though the operator's rotation assumed otherwise
- Invariant to test: cached credentials do not outlive their issuing token
- Expected Immunefi impact: extended validity window for a compromised token (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
