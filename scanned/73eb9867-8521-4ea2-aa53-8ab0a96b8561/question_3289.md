# Q3289: repoSync.initRepo — submodule gitattributes under shallow submodules

## Question
Can an unprivileged attacker who ships a submodule containing `.gitattributes` with a filter driver, under `--submodules=shallow` with `--depth` set, reach a state where — in the origin remote that relative-path submodules resolve against, set in initRepo() — the submodule checkout runs the filter command, breaking the invariant that checkout never executes repo-declared commands and yielding remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Ships a submodule containing `.gitattributes` with a filter driver. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the submodule checkout runs the filter command
- Invariant to test: checkout never executes repo-declared commands
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
