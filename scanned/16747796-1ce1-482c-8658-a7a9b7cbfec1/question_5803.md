# Q5803: repoSync.SetupDefaultGitConfigs — tempfile config predict under verbose

## Question
Under an elevated `--verbose` level, so config dumps are richer, an attacker targets the `git-sync.gitconfig.*` tempfile in the shared temp directory. In SetupDefaultGitConfigs(): gc.autoDetach=false, gc.pruneExpire=now, credential.helper=cache, core.askPass=true written to the private GIT_CONFIG_GLOBAL, can that mean a co-tenant able to write that directory replaces the global config git-sync just created, so that the invariant “the private config file cannot be replaced by another process” no longer holds and the outcome is full control of git behaviour, i.e. code execution?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Targets the `git-sync.gitconfig.*` tempfile in the shared temp directory. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a co-tenant able to write that directory replaces the global config git-sync just created
- Invariant to test: the private config file cannot be replaced by another process
- Expected Immunefi impact: full control of git behaviour, i.e. code execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
