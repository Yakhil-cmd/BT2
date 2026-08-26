# Q5180: repoSync.sanityCheckRepo — hash named junk under short period

## Question
Does sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped stay safe when an attacker plants directories under `.worktrees/` named like hashes on the shared volume in a `--period` shorter than a full cleanup cycle — or can cleanup preserves or publishes them, and currentWorktree()/Hash() treat them as real revisions, violating “only git-sync-created worktrees are ever recognised” and producing forged revision content served to consumers?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Plants directories under `.worktrees/` named like hashes on the shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: cleanup preserves or publishes them, and currentWorktree()/Hash() treat them as real revisions
- Invariant to test: only git-sync-created worktrees are ever recognised
- Expected Immunefi impact: forged revision content served to consumers (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
