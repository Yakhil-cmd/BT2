# Q4328: Exechook.Do — webhook timeout pileup under both hooks

## Question
Can an unprivileged attacker who makes the webhook endpoint stall just under --webhook-timeout every time, under a deployment using both exec and web hooks, reach a state where — in Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() — hook goroutines and retries accumulate against a frozen endpoint, breaking the invariant that hook concurrency is bounded and yielding resource exhaustion / denial of updates?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the webhook endpoint stall just under --webhook-timeout every time. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: hook goroutines and retries accumulate against a frozen endpoint
- Invariant to test: hook concurrency is bounded
- Expected Immunefi impact: resource exhaustion / denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
