# Q3610: repoSync.SyncRepo — refs replace substitution under depth1

## Question
Under a deployment using `--depth=1` (the documented shallow default for large repos), an attacker pushes `refs/replace/<sha>` objects that remap the commit --ref points at. In the hash resolution and change-detection logic in SyncRepo() (`rev-parse FETCH_HEAD^{}`, currentHash vs remoteHash, `reset --soft`), can that mean rev-parse and checkout disagree about which objects back the published hash, so the symlink's hash leaf no longer describes the delivered bytes, so that the invariant “the hash in the symlink leaf is exactly the content checked out” no longer holds and the outcome is content/identity mismatch: consumers verify a hash that does not match delivered files?

## Target
- File/function: [main.go](main.go) — `repoSync.SyncRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes `refs/replace/<sha>` objects that remap the commit --ref points at. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: rev-parse and checkout disagree about which objects back the published hash, so the symlink's hash leaf no longer describes the delivered bytes
- Invariant to test: the hash in the symlink leaf is exactly the content checked out
- Expected Immunefi impact: content/identity mismatch: consumers verify a hash that does not match delivered files (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
