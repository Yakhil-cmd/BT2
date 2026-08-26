# Q4856: repoSync.sanityCheckRepo — dir is empty race under short period

## Question
Under a `--period` shorter than a full cleanup cycle, an attacker adds and removes entries in the root on a shared volume around dirIsEmpty(). In sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped, can that mean the emptiness decision flips, sending the code down the init-or-wipe path at the attacker's choosing, so that the invariant “root state classification is atomic with respect to outside writers” no longer holds and the outcome is attacker-triggered wipe of published data?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Adds and removes entries in the root on a shared volume around dirIsEmpty(). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the emptiness decision flips, sending the code down the init-or-wipe path at the attacker's choosing
- Invariant to test: root state classification is atomic with respect to outside writers
- Expected Immunefi impact: attacker-triggered wipe of published data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
