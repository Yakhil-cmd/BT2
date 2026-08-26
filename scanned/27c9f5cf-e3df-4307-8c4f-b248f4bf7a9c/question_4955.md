# Q4955: removeDirContentsIf — hash named junk under gc aggressive

## Question
Starting from `--git-gc=aggressive`, can an attacker who plants directories under `.worktrees/` named like hashes on the shared volume drive removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents to a state where cleanup preserves or publishes them, and currentWorktree()/Hash() treat them as real revisions, defeating “only git-sync-created worktrees are ever recognised” and causing forged revision content served to consumers?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Plants directories under `.worktrees/` named like hashes on the shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: cleanup preserves or publishes them, and currentWorktree()/Hash() treat them as real revisions
- Invariant to test: only git-sync-created worktrees are ever recognised
- Expected Immunefi impact: forged revision content served to consumers (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
