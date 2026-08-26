# Q4699: repoSync.isShallow — origin url churn under hash pinned

## Question
Can an unprivileged attacker who gets the remote to redirect the fetch (HTTP redirect on the smart-http endpoint) to a different repository path, under `--ref` pinned to a full commit hash, where git-sync sleeps forever after the first successful sync, reach a state where — in the shallowness probe isShallow() and its `--unshallow` decision — initRepo()'s `remote get-url origin` comparison still matches --repo while objects come from elsewhere, and relative-path submodules then resolve against the wrong origin, breaking the invariant that the origin remote used for objects and for relative submodules is exactly --repo and yielding unauthorized content published, including via relative submodule resolution?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Gets the remote to redirect the fetch (HTTP redirect on the smart-http endpoint) to a different repository path. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: initRepo()'s `remote get-url origin` comparison still matches --repo while objects come from elsewhere, and relative-path submodules then resolve against the wrong origin
- Invariant to test: the origin remote used for objects and for relative submodules is exactly --repo
- Expected Immunefi impact: unauthorized content published, including via relative submodule resolution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
