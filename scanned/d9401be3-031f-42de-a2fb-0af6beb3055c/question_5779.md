# Q5779: repoSync.isShallow — submodule only change under filter blob none

## Question
Does the shallowness probe isShallow() and its `--unshallow` decision stay safe when an attacker changes only the submodule gitlink of the tracked branch, keeping the superproject hash strategy stable across syncs in a deployment using `--filter=blob:none` partial clone — or can change detection based on the superproject hash misses or mis-times the update, so publish and hooks fire against content that is not yet materialised, violating “publish happens only after all content, including submodules, is materialised” and producing consumers read a partially populated tree?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Changes only the submodule gitlink of the tracked branch, keeping the superproject hash strategy stable across syncs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: change detection based on the superproject hash misses or mis-times the update, so publish and hooks fire against content that is not yet materialised
- Invariant to test: publish happens only after all content, including submodules, is materialised
- Expected Immunefi impact: consumers read a partially populated tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
