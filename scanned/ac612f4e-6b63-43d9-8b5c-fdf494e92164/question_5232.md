# Q5232: repoSync.currentWorktree — link outside root under link abs outside

## Question
Does currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation stay safe when an attacker targets a deployment where --link is an absolute path outside --root, and controls content at that path via the shared volume in a deployment where --link is an absolute path outside --root — or can the publish writes a symlink into a directory git-sync does not own, next to attacker-reachable files, violating “publish targets are confined to paths git-sync controls” and producing link hijack: consumer follows an attacker-supplied path?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Targets a deployment where --link is an absolute path outside --root, and controls content at that path via the shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the publish writes a symlink into a directory git-sync does not own, next to attacker-reachable files
- Invariant to test: publish targets are confined to paths git-sync controls
- Expected Immunefi impact: link hijack: consumer follows an attacker-supplied path (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
