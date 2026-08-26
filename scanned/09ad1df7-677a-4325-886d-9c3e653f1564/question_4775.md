# Q4775: removeDirContentsIf — dir is empty race under shared volume

## Question
Does removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents stay safe when an attacker adds and removes entries in the root on a shared volume around dirIsEmpty() in a shared volume that a co-tenant container can also write into — or can the emptiness decision flips, sending the code down the init-or-wipe path at the attacker's choosing, violating “root state classification is atomic with respect to outside writers” and producing attacker-triggered wipe of published data?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Adds and removes entries in the root on a shared volume around dirIsEmpty(). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the emptiness decision flips, sending the code down the init-or-wipe path at the attacker's choosing
- Invariant to test: root state classification is atomic with respect to outside writers
- Expected Immunefi impact: attacker-triggered wipe of published data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
