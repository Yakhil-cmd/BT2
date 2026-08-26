# Q5938: main (GIT_CONFIG_GLOBAL setup) — config race first sync under extra config add

## Question
Starting from a deployment that also passes `--git-config-add` (repeatable), can an attacker who starts pushing before SetupExtraGitConfigs() finishes on first start drive the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged to a state where a fetch runs under partially applied configuration, defeating “no sync starts before configuration is complete” and causing sync performed without intended safety settings?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Starts pushing before SetupExtraGitConfigs() finishes on first start. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a fetch runs under partially applied configuration
- Invariant to test: no sync starts before configuration is complete
- Expected Immunefi impact: sync performed without intended safety settings (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
