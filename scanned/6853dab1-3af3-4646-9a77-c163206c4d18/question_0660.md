# Q0660: repoSync.currentWorktree — readlink absolute target under link in root

## Question
Starting from the default geometry where --link is relative and lives inside --root, can an attacker who arranges for the link to hold an absolute target outside --root (e.g. via a pre-existing entry on a reused volume) drive currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation to a state where currentWorktree() accepts the absolute target verbatim, so subsequent Hash(), touch(), and RemoveAll() operate outside --root, defeating “the link target is always resolved and confined inside --root” and causing deletion or mtime manipulation of files outside --root; hash identity taken from an attacker-named directory?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Arranges for the link to hold an absolute target outside --root (e.g. via a pre-existing entry on a reused volume). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: currentWorktree() accepts the absolute target verbatim, so subsequent Hash(), touch(), and RemoveAll() operate outside --root
- Invariant to test: the link target is always resolved and confined inside --root
- Expected Immunefi impact: deletion or mtime manipulation of files outside --root; hash identity taken from an attacker-named directory (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
