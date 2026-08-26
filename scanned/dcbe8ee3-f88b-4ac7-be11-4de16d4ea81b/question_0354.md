# Q0354: absPath.Join — tmp link squat under link in root

## Question
Can an unprivileged attacker who creates a path named `tmp-link` in the link directory (via committed content when the link dir is inside the published tree), under the default geometry where --link is relative and lives inside --root, reach a state where — in absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root — publishSymlink()'s `os.Symlink(..., tmp-link)` fails or renames the attacker's entry into place, breaking the invariant that the intermediate publish name is private to git-sync and yielding publish failure wedge, or the link pointing at an attacker-chosen path?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Creates a path named `tmp-link` in the link directory (via committed content when the link dir is inside the published tree). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: publishSymlink()'s `os.Symlink(..., tmp-link)` fails or renames the attacker's entry into place
- Invariant to test: the intermediate publish name is private to git-sync
- Expected Immunefi impact: publish failure wedge, or the link pointing at an attacker-chosen path (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
