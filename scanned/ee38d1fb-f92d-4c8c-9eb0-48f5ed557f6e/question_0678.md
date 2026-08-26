# Q0678: absPath.Join — readlink absolute target under link in root

## Question
Under the default geometry where --link is relative and lives inside --root, an attacker arranges for the link to hold an absolute target outside --root (e.g. via a pre-existing entry on a reused volume). In absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root, can that mean currentWorktree() accepts the absolute target verbatim, so subsequent Hash(), touch(), and RemoveAll() operate outside --root, so that the invariant “the link target is always resolved and confined inside --root” no longer holds and the outcome is deletion or mtime manipulation of files outside --root; hash identity taken from an attacker-named directory?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Arranges for the link to hold an absolute target outside --root (e.g. via a pre-existing entry on a reused volume). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: currentWorktree() accepts the absolute target verbatim, so subsequent Hash(), touch(), and RemoveAll() operate outside --root
- Invariant to test: the link target is always resolved and confined inside --root
- Expected Immunefi impact: deletion or mtime manipulation of files outside --root; hash identity taken from an attacker-named directory (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
