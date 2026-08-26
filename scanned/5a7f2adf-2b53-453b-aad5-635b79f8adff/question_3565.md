# Q3565: repoSync.fetch — refs replace substitution under first sync

## Question
Starting from the very first sync after container start, when the root is empty and syncCount is 0, can an attacker who pushes `refs/replace/<sha>` objects that remap the commit --ref points at drive the argv assembled in fetch() (`fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc` plus --depth/--unshallow/--filter) to a state where rev-parse and checkout disagree about which objects back the published hash, so the symlink's hash leaf no longer describes the delivered bytes, defeating “the hash in the symlink leaf is exactly the content checked out” and causing content/identity mismatch: consumers verify a hash that does not match delivered files?

## Target
- File/function: [main.go](main.go) — `repoSync.fetch`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes `refs/replace/<sha>` objects that remap the commit --ref points at. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: rev-parse and checkout disagree about which objects back the published hash, so the symlink's hash leaf no longer describes the delivered bytes
- Invariant to test: the hash in the symlink leaf is exactly the content checked out
- Expected Immunefi impact: content/identity mismatch: consumers verify a hash that does not match delivered files (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
