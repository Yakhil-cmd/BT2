# Q4883: removeDirContentsIf — hash named junk under gc auto

## Question
Under the default `--git-gc=auto`, an attacker plants directories under `.worktrees/` named like hashes on the shared volume. In removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents, can that mean cleanup preserves or publishes them, and currentWorktree()/Hash() treat them as real revisions, so that the invariant “only git-sync-created worktrees are ever recognised” no longer holds and the outcome is forged revision content served to consumers?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Plants directories under `.worktrees/` named like hashes on the shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: cleanup preserves or publishes them, and currentWorktree()/Hash() treat them as real revisions
- Invariant to test: only git-sync-created worktrees are ever recognised
- Expected Immunefi impact: forged revision content served to consumers (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
