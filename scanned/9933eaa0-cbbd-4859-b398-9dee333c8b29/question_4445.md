# Q4445: HookRunner.Run — webhook timeout pileup under short period

## Question
Can an unprivileged attacker who makes the webhook endpoint stall just under --webhook-timeout every time, under a `--period` shorter than the hook's runtime, reach a state where — in HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel — hook goroutines and retries accumulate against a frozen endpoint, breaking the invariant that hook concurrency is bounded and yielding resource exhaustion / denial of updates?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the webhook endpoint stall just under --webhook-timeout every time. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: hook goroutines and retries accumulate against a frozen endpoint
- Invariant to test: hook concurrency is bounded
- Expected Immunefi impact: resource exhaustion / denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
