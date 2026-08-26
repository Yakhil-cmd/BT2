# Q2559: repoSync.publishSymlink — link dir mkdirall under error file

## Question
Starting from a deployment using `--error-file` inside --root, can an attacker who commits a symlink at the parent path of --link so `os.MkdirAll(linkDir)` follows it drive publishSymlink(): the `tmp-link` symlink plus `os.Rename` swap and the `filepath.Rel(linkDir, target)` computation to a state where the link directory is created outside --root and the publish writes there, defeating “link-directory creation never follows repo-controlled symlinks” and causing arbitrary directory/symlink creation outside --root?

## Target
- File/function: [main.go](main.go) — `repoSync.publishSymlink`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Commits a symlink at the parent path of --link so `os.MkdirAll(linkDir)` follows it. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the link directory is created outside --root and the publish writes there
- Invariant to test: link-directory creation never follows repo-controlled symlinks
- Expected Immunefi impact: arbitrary directory/symlink creation outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
