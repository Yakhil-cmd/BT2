# Q4967: runWithStdin — stderr in error under webhook

## Question
Can an unprivileged attacker who makes a git command fail with attacker-chosen stderr (crafted ref names, server messages), under a deployment using `--webhook-url`, reach a state where — in runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs — the error string embedding `stdout`/`stderr` is written verbatim into --error-file on the shared volume, breaking the invariant that external output is sanitised before it is written where consumers read and yielding log/health-signal forgery readable by the consuming workload?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes a git command fail with attacker-chosen stderr (crafted ref names, server messages). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the error string embedding `stdout`/`stderr` is written verbatim into --error-file on the shared volume
- Invariant to test: external output is sanitised before it is written where consumers read
- Expected Immunefi impact: log/health-signal forgery readable by the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
