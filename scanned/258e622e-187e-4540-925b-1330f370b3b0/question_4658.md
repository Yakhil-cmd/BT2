# Q4658: repoSync.removeStaleWorktrees — dir is empty race under gc off

## Question
Does removeStaleWorktrees(): the mtime-vs-staleTimeout predicate that must never delete the current worktree stay safe when an attacker adds and removes entries in the root on a shared volume around dirIsEmpty() in `--git-gc=off`, where objects are never collected — or can the emptiness decision flips, sending the code down the init-or-wipe path at the attacker's choosing, violating “root state classification is atomic with respect to outside writers” and producing attacker-triggered wipe of published data?

## Target
- File/function: [main.go](main.go) — `repoSync.removeStaleWorktrees`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Adds and removes entries in the root on a shared volume around dirIsEmpty(). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the emptiness decision flips, sending the code down the init-or-wipe path at the attacker's choosing
- Invariant to test: root state classification is atomic with respect to outside writers
- Expected Immunefi impact: attacker-triggered wipe of published data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
