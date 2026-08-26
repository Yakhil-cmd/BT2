# Q0533: repoSync.removeWorktree — dotgit case variant under prepub hook

## Question
Under a deployment using `--pre-publish-exechook-command`, which touches the worktree before publish, an attacker commits a tree entry named with a case or Unicode variant of `.git` (`.GIT`, `.gIt`, `git~1`). In removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`), can that mean the checkout populates a directory git later treats as repository metadata, letting committed config or hooks take effect, so that the invariant “repository content can never become repository metadata” no longer holds and the outcome is code execution in the git-sync container on the next git invocation?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits a tree entry named with a case or Unicode variant of `.git` (`.GIT`, `.gIt`, `git~1`). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the checkout populates a directory git later treats as repository metadata, letting committed config or hooks take effect
- Invariant to test: repository content can never become repository metadata
- Expected Immunefi impact: code execution in the git-sync container on the next git invocation (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: build the malicious commit locally, sync once, then assert nothing was created or modified outside --root (`find / -newer` on a scratch container)
