# Q0326: repoSync.createWorktree — dotgit case variant under default flags

## Question
Under a default deployment (no sparse checkout, submodules recursive by default), an attacker commits a tree entry named with a case or Unicode variant of `.git` (`.GIT`, `.gIt`, `git~1`). In createWorktree() and its `worktree add --force --detach <path> <hash> --no-checkout`, can that mean the checkout populates a directory git later treats as repository metadata, letting committed config or hooks take effect, so that the invariant “repository content can never become repository metadata” no longer holds and the outcome is code execution in the git-sync container on the next git invocation?

## Target
- File/function: [main.go](main.go) — `repoSync.createWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits a tree entry named with a case or Unicode variant of `.git` (`.GIT`, `.gIt`, `git~1`). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the checkout populates a directory git later treats as repository metadata, letting committed config or hooks take effect
- Invariant to test: repository content can never become repository metadata
- Expected Immunefi impact: code execution in the git-sync container on the next git invocation (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
