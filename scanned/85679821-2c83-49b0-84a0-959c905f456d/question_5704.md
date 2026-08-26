# Q5704: repoSync.SetupExtraGitConfigs — tempfile config predict under submodules recursive

## Question
Starting from the default `--submodules=recursive`, so config affects submodule transports, can an attacker who targets the `git-sync.gitconfig.*` tempfile in the shared temp directory drive SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner to a state where a co-tenant able to write that directory replaces the global config git-sync just created, defeating “the private config file cannot be replaced by another process” and causing full control of git behaviour, i.e. code execution?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Targets the `git-sync.gitconfig.*` tempfile in the shared temp directory. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a co-tenant able to write that directory replaces the global config git-sync just created
- Invariant to test: the private config file cannot be replaced by another process
- Expected Immunefi impact: full control of git behaviour, i.e. code execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
