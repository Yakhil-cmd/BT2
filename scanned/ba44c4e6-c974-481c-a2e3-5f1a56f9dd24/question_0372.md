# Q0372: repoSync.currentWorktree — tmp link squat under link abs outside

## Question
Starting from a deployment where --link is an absolute path outside --root, can an attacker who creates a path named `tmp-link` in the link directory (via committed content when the link dir is inside the published tree) drive currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation to a state where publishSymlink()'s `os.Symlink(..., tmp-link)` fails or renames the attacker's entry into place, defeating “the intermediate publish name is private to git-sync” and causing publish failure wedge, or the link pointing at an attacker-chosen path?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Creates a path named `tmp-link` in the link directory (via committed content when the link dir is inside the published tree). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: publishSymlink()'s `os.Symlink(..., tmp-link)` fails or renames the attacker's entry into place
- Invariant to test: the intermediate publish name is private to git-sync
- Expected Immunefi impact: publish failure wedge, or the link pointing at an attacker-chosen path (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
