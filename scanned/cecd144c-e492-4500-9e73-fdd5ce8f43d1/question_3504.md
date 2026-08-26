# Q3504: repoSync.currentWorktree — error file collision under touch file

## Question
Does currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation stay safe when an attacker commits a file at the path --error-file resolves to, when the error file lives inside the published tree in a deployment using `--touch-file` for readiness signalling — or can logging.writeContent()/DeleteErrorFile() overwrite or delete repo content, and repo content masquerades as git-sync's error report, violating “the error file is git-sync-owned and outside any published tree” and producing forged health signals to the consumer plus mutation of published content?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Commits a file at the path --error-file resolves to, when the error file lives inside the published tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: logging.writeContent()/DeleteErrorFile() overwrite or delete repo content, and repo content masquerades as git-sync's error report
- Invariant to test: the error file is git-sync-owned and outside any published tree
- Expected Immunefi impact: forged health signals to the consumer plus mutation of published content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
