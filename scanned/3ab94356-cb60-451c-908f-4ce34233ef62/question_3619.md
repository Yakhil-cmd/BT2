# Q3619: repoSync.isShallow — refs replace substitution under depth1

## Question
Does the shallowness probe isShallow() and its `--unshallow` decision stay safe when an attacker pushes `refs/replace/<sha>` objects that remap the commit --ref points at in a deployment using `--depth=1` (the documented shallow default for large repos) — or can rev-parse and checkout disagree about which objects back the published hash, so the symlink's hash leaf no longer describes the delivered bytes, violating “the hash in the symlink leaf is exactly the content checked out” and producing content/identity mismatch: consumers verify a hash that does not match delivered files?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes `refs/replace/<sha>` objects that remap the commit --ref points at. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: rev-parse and checkout disagree about which objects back the published hash, so the symlink's hash leaf no longer describes the delivered bytes
- Invariant to test: the hash in the symlink leaf is exactly the content checked out
- Expected Immunefi impact: content/identity mismatch: consumers verify a hash that does not match delivered files (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
