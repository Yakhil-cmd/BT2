# Q4337: HookRunner.Run — webhook timeout pileup under both hooks

## Question
Under a deployment using both exec and web hooks, an attacker makes the webhook endpoint stall just under --webhook-timeout every time. In HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel, can that mean hook goroutines and retries accumulate against a frozen endpoint, so that the invariant “hook concurrency is bounded” no longer holds and the outcome is resource exhaustion / denial of updates?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the webhook endpoint stall just under --webhook-timeout every time. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: hook goroutines and retries accumulate against a frozen endpoint
- Invariant to test: hook concurrency is bounded
- Expected Immunefi impact: resource exhaustion / denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
