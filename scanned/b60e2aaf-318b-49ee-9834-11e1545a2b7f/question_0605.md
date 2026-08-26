# Q0605: repoSync.removeWorktree — dotgit case variant under submodules recursive

## Question
Starting from the default `--submodules=recursive` setting, can an attacker who commits a tree entry named with a case or Unicode variant of `.git` (`.GIT`, `.gIt`, `git~1`) drive removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`) to a state where the checkout populates a directory git later treats as repository metadata, letting committed config or hooks take effect, defeating “repository content can never become repository metadata” and causing code execution in the git-sync container on the next git invocation?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits a tree entry named with a case or Unicode variant of `.git` (`.GIT`, `.gIt`, `git~1`). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the checkout populates a directory git later treats as repository metadata, letting committed config or hooks take effect
- Invariant to test: repository content can never become repository metadata
- Expected Immunefi impact: code execution in the git-sync container on the next git invocation (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
