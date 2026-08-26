# Q3440: repoSync.sanityCheckWorktree — hardlink and mode bits under prepub hook

## Question
Under a deployment using `--pre-publish-exechook-command`, which touches the worktree before publish, an attacker commits files with setgid/sticky-adjacent modes, or many hardlink-shaped duplicates. In sanityCheckWorktree() (`dirIsEmpty`, `rev-parse HEAD`, `fsck --connectivity-only`), can that mean checked-out permissions combined with the --group-write umask make published files writable by a co-tenant, so that the invariant “published files are never writable by processes outside git-sync” no longer holds and the outcome is co-tenant tampering with published code before the consumer reads it?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits files with setgid/sticky-adjacent modes, or many hardlink-shaped duplicates. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: checked-out permissions combined with the --group-write umask make published files writable by a co-tenant
- Invariant to test: published files are never writable by processes outside git-sync
- Expected Immunefi impact: co-tenant tampering with published code before the consumer reads it (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
