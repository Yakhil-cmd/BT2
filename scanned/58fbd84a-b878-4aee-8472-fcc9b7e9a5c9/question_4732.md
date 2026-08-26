# Q4732: repoSync.SetupExtraGitConfigs — include if under submodules recursive

## Question
Can an unprivileged attacker who commits config with `include.path` / `includeIf` chains pointing at repo files, under the default `--submodules=recursive`, so config affects submodule transports, reach a state where — in SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner — git pulls attacker-authored config out of the checked-out tree, breaking the invariant that config never includes files from the working tree and yielding code execution or credential redirection?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Commits config with `include.path` / `includeIf` chains pointing at repo files. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git pulls attacker-authored config out of the checked-out tree
- Invariant to test: config never includes files from the working tree
- Expected Immunefi impact: code execution or credential redirection (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
