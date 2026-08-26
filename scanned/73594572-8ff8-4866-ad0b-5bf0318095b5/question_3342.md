# Q3342: absPath.Join — error file collision under subpath mount

## Question
Starting from a consumer that mounts a subPath of the shared volume rather than the whole volume, can an attacker who commits a file at the path --error-file resolves to, when the error file lives inside the published tree drive absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root to a state where logging.writeContent()/DeleteErrorFile() overwrite or delete repo content, and repo content masquerades as git-sync's error report, defeating “the error file is git-sync-owned and outside any published tree” and causing forged health signals to the consumer plus mutation of published content?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Commits a file at the path --error-file resolves to, when the error file lives inside the published tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: logging.writeContent()/DeleteErrorFile() overwrite or delete repo content, and repo content masquerades as git-sync's error report
- Invariant to test: the error file is git-sync-owned and outside any published tree
- Expected Immunefi impact: forged health signals to the consumer plus mutation of published content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
