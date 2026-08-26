# Q1870: main (GIT_CONFIG_GLOBAL setup) — config value newline under http auth

## Question
Does the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged stay safe when an attacker supplies a value that reaches `git config --global <key> <val>` containing newlines or section-terminating characters in HTTPS auth, where credential caching is live — or can the written config file gains extra keys the operator never specified, violating “one config setting writes exactly one key” and producing silent injection of dangerous git config (transport helpers, aliases)?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Supplies a value that reaches `git config --global <key> <val>` containing newlines or section-terminating characters. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the written config file gains extra keys the operator never specified
- Invariant to test: one config setting writes exactly one key
- Expected Immunefi impact: silent injection of dangerous git config (transport helpers, aliases) (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
