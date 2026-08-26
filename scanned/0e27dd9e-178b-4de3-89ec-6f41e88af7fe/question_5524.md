# Q5524: repoSync.SetupExtraGitConfigs — tempfile config predict under default config

## Question
Does SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner stay safe when an attacker targets the `git-sync.gitconfig.*` tempfile in the shared temp directory in the default configuration git-sync installs at startup — or can a co-tenant able to write that directory replaces the global config git-sync just created, violating “the private config file cannot be replaced by another process” and producing full control of git behaviour, i.e. code execution?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Targets the `git-sync.gitconfig.*` tempfile in the shared temp directory. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a co-tenant able to write that directory replaces the global config git-sync just created
- Invariant to test: the private config file cannot be replaced by another process
- Expected Immunefi impact: full control of git behaviour, i.e. code execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: dump `git config list -z` under GIT_CONFIG_GLOBAL after the fixture sync and assert the effective keys equal the intended set
