# Q1175: removeDirContentsIf — removeall escape under stale timeout zero

## Question
Does removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents stay safe when an attacker places a symlinked directory entry inside a directory being wiped in the default zero `--stale-worktree-timeout`, where non-current worktrees are reclaimed immediately — or can RemoveAll acts on, or fails because of, a path outside --root, violating “content removal is confined to --root” and producing deletion of co-mounted data outside --root?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Places a symlinked directory entry inside a directory being wiped. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: RemoveAll acts on, or fails because of, a path outside --root
- Invariant to test: content removal is confined to --root
- Expected Immunefi impact: deletion of co-mounted data outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
