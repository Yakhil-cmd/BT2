# Q5991: repoSync.CallAskPassURL — token persist after fail under ssh default

## Question
Starting from SSH auth with the default `--ssh-known-hosts=false`, can an attacker who makes the sync fail after the token is stored in the helper cache drive CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response to a state where the token remains cached and usable for the full hour even though the operator's rotation assumed otherwise, defeating “cached credentials do not outlive their issuing token” and causing extended validity window for a compromised token?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Makes the sync fail after the token is stored in the helper cache. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the token remains cached and usable for the full hour even though the operator's rotation assumed otherwise
- Invariant to test: cached credentials do not outlive their issuing token
- Expected Immunefi impact: extended validity window for a compromised token (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
