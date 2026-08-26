# Q1076: repoSync.sanityCheckRepo — removeall escape under gc aggressive

## Question
Can an unprivileged attacker who places a symlinked directory entry inside a directory being wiped, under `--git-gc=aggressive`, reach a state where — in sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped — RemoveAll acts on, or fails because of, a path outside --root, breaking the invariant that content removal is confined to --root and yielding deletion of co-mounted data outside --root?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Places a symlinked directory entry inside a directory being wiped. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: RemoveAll acts on, or fails because of, a path outside --root
- Invariant to test: content removal is confined to --root
- Expected Immunefi impact: deletion of co-mounted data outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
