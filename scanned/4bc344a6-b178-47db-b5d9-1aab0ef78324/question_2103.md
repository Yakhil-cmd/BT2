# Q2103: repoSync.CallAskPassURL — github token in worktree under ssh default

## Question
Starting from SSH auth with the default `--ssh-known-hosts=false`, can an attacker who arranges any path where the credential blob or token is written under --root rather than into the helper drive CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response to a state where the token lands on the shared volume, defeating “tokens exist only in memory and in the credential helper” and causing GitHub App token disclosure to the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Arranges any path where the credential blob or token is written under --root rather than into the helper. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the token lands on the shared volume
- Invariant to test: tokens exist only in memory and in the credential helper
- Expected Immunefi impact: GitHub App token disclosure to the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
