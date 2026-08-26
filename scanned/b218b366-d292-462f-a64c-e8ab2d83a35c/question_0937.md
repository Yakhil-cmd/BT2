# Q0937: repoSync.fetch — annotated tag peel to nonc0mmit under crash resume

## Question
Does the argv assembled in fetch() (`fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc` plus --depth/--unshallow/--filter) stay safe when an attacker pushes an annotated tag whose target is a tree, a blob, or another tag chain rather than a commit in a resume after the previous process died between fetch and publish, leaving partial state in --root — or can `rev-parse FETCH_HEAD^{}` returns a non-commit object id that is then fed to `reset --soft`, `worktree add`, and worktree naming, violating “every value used as a worktree name and reset target is a commit object id” and producing sync wedge / crash loop, or a worktree whose leaf name is not a commit hash, breaking the symlink contract?

## Target
- File/function: [main.go](main.go) — `repoSync.fetch`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes an annotated tag whose target is a tree, a blob, or another tag chain rather than a commit. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `rev-parse FETCH_HEAD^{}` returns a non-commit object id that is then fed to `reset --soft`, `worktree add`, and worktree naming
- Invariant to test: every value used as a worktree name and reset target is a commit object id
- Expected Immunefi impact: sync wedge / crash loop, or a worktree whose leaf name is not a commit hash, breaking the symlink contract (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
