# Q5884: repoSync.SetupExtraGitConfigs — config race first sync under extra config

## Question
Can an unprivileged attacker who starts pushing before SetupExtraGitConfigs() finishes on first start, under a deployment that also passes `--git-config`, reach a state where — in SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner — a fetch runs under partially applied configuration, breaking the invariant that no sync starts before configuration is complete and yielding sync performed without intended safety settings?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Starts pushing before SetupExtraGitConfigs() finishes on first start. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a fetch runs under partially applied configuration
- Invariant to test: no sync starts before configuration is complete
- Expected Immunefi impact: sync performed without intended safety settings (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
