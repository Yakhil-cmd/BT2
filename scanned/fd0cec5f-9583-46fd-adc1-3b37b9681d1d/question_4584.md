# Q4584: repoSync.currentWorktree — unicode leaf under link abs outside

## Question
Can an unprivileged attacker who produces worktree leaf names containing separators or NUL-adjacent bytes via crafted object ids surfaced in logs, under a deployment where --link is an absolute path outside --root, reach a state where — in currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation — Split()/Base() mis-parse the leaf, so hash identity and path identity diverge, breaking the invariant that leaf parsing is exact for every value that reaches it and yielding forged revision identity in the published contract?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Produces worktree leaf names containing separators or NUL-adjacent bytes via crafted object ids surfaced in logs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: Split()/Base() mis-parse the leaf, so hash identity and path identity diverge
- Invariant to test: leaf parsing is exact for every value that reaches it
- Expected Immunefi impact: forged revision identity in the published contract (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
