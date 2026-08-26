# Q4913: HookRunner.Run — stderr in error under prepub hook

## Question
Under a deployment using `--pre-publish-exechook-command`, an attacker makes a git command fail with attacker-chosen stderr (crafted ref names, server messages). In HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel, can that mean the error string embedding `stdout`/`stderr` is written verbatim into --error-file on the shared volume, so that the invariant “external output is sanitised before it is written where consumers read” no longer holds and the outcome is log/health-signal forgery readable by the consuming workload?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes a git command fail with attacker-chosen stderr (crafted ref names, server messages). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the error string embedding `stdout`/`stderr` is written verbatim into --error-file on the shared volume
- Invariant to test: external output is sanitised before it is written where consumers read
- Expected Immunefi impact: log/health-signal forgery readable by the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
