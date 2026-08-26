# Q0802: repoSync.SyncRepo — annotated tag peel to nonc0mmit under hash pinned

## Question
Starting from `--ref` pinned to a full commit hash, where git-sync sleeps forever after the first successful sync, can an attacker who pushes an annotated tag whose target is a tree, a blob, or another tag chain rather than a commit drive the hash resolution and change-detection logic in SyncRepo() (`rev-parse FETCH_HEAD^{}`, currentHash vs remoteHash, `reset --soft`) to a state where `rev-parse FETCH_HEAD^{}` returns a non-commit object id that is then fed to `reset --soft`, `worktree add`, and worktree naming, defeating “every value used as a worktree name and reset target is a commit object id” and causing sync wedge / crash loop, or a worktree whose leaf name is not a commit hash, breaking the symlink contract?

## Target
- File/function: [main.go](main.go) — `repoSync.SyncRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes an annotated tag whose target is a tree, a blob, or another tag chain rather than a commit. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `rev-parse FETCH_HEAD^{}` returns a non-commit object id that is then fed to `reset --soft`, `worktree add`, and worktree naming
- Invariant to test: every value used as a worktree name and reset target is a commit object id
- Expected Immunefi impact: sync wedge / crash loop, or a worktree whose leaf name is not a commit hash, breaking the symlink contract (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
