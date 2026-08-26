# Q0019: repoSync.isShallow — refname ambiguity tag over branch under first sync

## Question
Does the shallowness probe isShallow() and its `--unshallow` decision stay safe when an attacker pushes a tag whose name is identical to the branch named by --ref (e.g. tag `main` alongside branch `main`) in the very first sync after container start, when the root is empty and syncCount is 0 — or can the unqualified refspec passed to `git fetch <repo> <ref>` resolves to the attacker's tag instead of the branch, so FETCH_HEAD is an object the branch owner never approved, violating “the published hash is always the tip of the ref the operator named, not a same-named ref of a different type” and producing unauthorized content published to consumers (supply-chain code substitution into the workload)?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes a tag whose name is identical to the branch named by --ref (e.g. tag `main` alongside branch `main`). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the unqualified refspec passed to `git fetch <repo> <ref>` resolves to the attacker's tag instead of the branch, so FETCH_HEAD is an object the branch owner never approved
- Invariant to test: the published hash is always the tip of the ref the operator named, not a same-named ref of a different type
- Expected Immunefi impact: unauthorized content published to consumers (supply-chain code substitution into the workload) (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
