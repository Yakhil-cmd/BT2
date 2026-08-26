# Q5380: repoSync.SetupExtraGitConfigs — fsmonitor hook under submodules recursive

## Question
Does SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner stay safe when an attacker gets `core.fsmonitor` set to a path inside the checked-out tree in the default `--submodules=recursive`, so config affects submodule transports — or can git executes the attacker's file on the next repository operation, violating “no config points at executables inside the working tree” and producing remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets `core.fsmonitor` set to a path inside the checked-out tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git executes the attacker's file on the next repository operation
- Invariant to test: no config points at executables inside the working tree
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
