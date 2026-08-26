# Q0957: repoSync.worktreeFor — readlink absolute target under error file

## Question
Can an unprivileged attacker who arranges for the link to hold an absolute target outside --root (e.g. via a pre-existing entry on a reused volume), under a deployment using `--error-file` inside --root, reach a state where — in worktreeFor()/worktree.Hash(), which derive identity from the leaf name of `.worktrees/<hash>` — currentWorktree() accepts the absolute target verbatim, so subsequent Hash(), touch(), and RemoveAll() operate outside --root, breaking the invariant that the link target is always resolved and confined inside --root and yielding deletion or mtime manipulation of files outside --root; hash identity taken from an attacker-named directory?

## Target
- File/function: [main.go](main.go) — `repoSync.worktreeFor / worktree.Hash`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Arranges for the link to hold an absolute target outside --root (e.g. via a pre-existing entry on a reused volume). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: currentWorktree() accepts the absolute target verbatim, so subsequent Hash(), touch(), and RemoveAll() operate outside --root
- Invariant to test: the link target is always resolved and confined inside --root
- Expected Immunefi impact: deletion or mtime manipulation of files outside --root; hash identity taken from an attacker-named directory (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
