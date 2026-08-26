# Q0363: repoSync.publishSymlink — tmp link squat under link abs outside

## Question
Does publishSymlink(): the `tmp-link` symlink plus `os.Rename` swap and the `filepath.Rel(linkDir, target)` computation stay safe when an attacker creates a path named `tmp-link` in the link directory (via committed content when the link dir is inside the published tree) in a deployment where --link is an absolute path outside --root — or can publishSymlink()'s `os.Symlink(..., tmp-link)` fails or renames the attacker's entry into place, violating “the intermediate publish name is private to git-sync” and producing publish failure wedge, or the link pointing at an attacker-chosen path?

## Target
- File/function: [main.go](main.go) — `repoSync.publishSymlink`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Creates a path named `tmp-link` in the link directory (via committed content when the link dir is inside the published tree). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: publishSymlink()'s `os.Symlink(..., tmp-link)` fails or renames the attacker's entry into place
- Invariant to test: the intermediate publish name is private to git-sync
- Expected Immunefi impact: publish failure wedge, or the link pointing at an attacker-chosen path (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
