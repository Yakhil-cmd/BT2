# Q4825: repoSync.fetch — origin url churn under crash resume

## Question
Does the argv assembled in fetch() (`fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc` plus --depth/--unshallow/--filter) stay safe when an attacker gets the remote to redirect the fetch (HTTP redirect on the smart-http endpoint) to a different repository path in a resume after the previous process died between fetch and publish, leaving partial state in --root — or can initRepo()'s `remote get-url origin` comparison still matches --repo while objects come from elsewhere, and relative-path submodules then resolve against the wrong origin, violating “the origin remote used for objects and for relative submodules is exactly --repo” and producing unauthorized content published, including via relative submodule resolution?

## Target
- File/function: [main.go](main.go) — `repoSync.fetch`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Gets the remote to redirect the fetch (HTTP redirect on the smart-http endpoint) to a different repository path. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: initRepo()'s `remote get-url origin` comparison still matches --repo while objects come from elsewhere, and relative-path submodules then resolve against the wrong origin
- Invariant to test: the origin remote used for objects and for relative submodules is exactly --repo
- Expected Immunefi impact: unauthorized content published, including via relative submodule resolution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
