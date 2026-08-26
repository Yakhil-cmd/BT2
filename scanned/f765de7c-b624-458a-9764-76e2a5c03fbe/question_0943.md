# Q0943: repoSync.SetupDefaultGitConfigs — core askpass flip under verbose

## Question
Does SetupDefaultGitConfigs(): gc.autoDetach=false, gc.pruneExpire=now, credential.helper=cache, core.askPass=true written to the private GIT_CONFIG_GLOBAL stay safe when an attacker gets any config layer to override `core.askPass=true` in an elevated `--verbose` level, so config dumps are richer — or can git prompts or invokes an attacker-reachable askpass program instead of failing closed, violating “git never prompts and never runs an unexpected askpass binary” and producing credential disclosure or a hung sync?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets any config layer to override `core.askPass=true`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git prompts or invokes an attacker-reachable askpass program instead of failing closed
- Invariant to test: git never prompts and never runs an unexpected askpass binary
- Expected Immunefi impact: credential disclosure or a hung sync (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
