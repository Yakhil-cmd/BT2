# Q4247: runWithStdin — webhook timeout pileup under exechook

## Question
Can an unprivileged attacker who makes the webhook endpoint stall just under --webhook-timeout every time, under a deployment using `--exechook-command`, reach a state where — in runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs — hook goroutines and retries accumulate against a frozen endpoint, breaking the invariant that hook concurrency is bounded and yielding resource exhaustion / denial of updates?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the webhook endpoint stall just under --webhook-timeout every time. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: hook goroutines and retries accumulate against a frozen endpoint
- Invariant to test: hook concurrency is bounded
- Expected Immunefi impact: resource exhaustion / denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
