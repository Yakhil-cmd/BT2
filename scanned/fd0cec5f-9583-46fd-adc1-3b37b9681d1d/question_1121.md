# Q1121: repoSync.cleanup — removeall escape under stale timeout set

## Question
Starting from `--stale-worktree-timeout` set to a non-zero value, can an attacker who places a symlinked directory entry inside a directory being wiped drive cleanup(): removeStaleWorktrees(), `worktree prune`, `reflog expire --expire-unreachable=all --all`, and the `gc` invocation to a state where RemoveAll acts on, or fails because of, a path outside --root, defeating “content removal is confined to --root” and causing deletion of co-mounted data outside --root?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Places a symlinked directory entry inside a directory being wiped. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: RemoveAll acts on, or fails because of, a path outside --root
- Invariant to test: content removal is confined to --root
- Expected Immunefi impact: deletion of co-mounted data outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
