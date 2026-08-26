# Q5864: repoSync.sanityCheckRepo — hardlink cross worktree under gc auto

## Question
Under the default `--git-gc=auto`, an attacker commits content that makes git share objects/hardlinks across worktrees so deleting one damages another. In sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped, can that mean reclaiming a stale worktree corrupts the live one, so that the invariant “worktrees are independently deletable” no longer holds and the outcome is corruption of published content mid-service?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Commits content that makes git share objects/hardlinks across worktrees so deleting one damages another. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: reclaiming a stale worktree corrupts the live one
- Invariant to test: worktrees are independently deletable
- Expected Immunefi impact: corruption of published content mid-service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
