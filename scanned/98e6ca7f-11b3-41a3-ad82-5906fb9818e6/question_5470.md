# Q5470: main (GIT_CONFIG_GLOBAL setup) — fsmonitor hook under gc always

## Question
Does the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged stay safe when an attacker gets `core.fsmonitor` set to a path inside the checked-out tree in `--git-gc=always`, so maintenance config matters every period — or can git executes the attacker's file on the next repository operation, violating “no config points at executables inside the working tree” and producing remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets `core.fsmonitor` set to a path inside the checked-out tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git executes the attacker's file on the next repository operation
- Invariant to test: no config points at executables inside the working tree
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
