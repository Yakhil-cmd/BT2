# Q5848: repoSync.SetupExtraGitConfigs — config race first sync under default config

## Question
Starting from the default configuration git-sync installs at startup, can an attacker who starts pushing before SetupExtraGitConfigs() finishes on first start drive SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner to a state where a fetch runs under partially applied configuration, defeating “no sync starts before configuration is complete” and causing sync performed without intended safety settings?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Starts pushing before SetupExtraGitConfigs() finishes on first start. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a fetch runs under partially applied configuration
- Invariant to test: no sync starts before configuration is complete
- Expected Immunefi impact: sync performed without intended safety settings (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
