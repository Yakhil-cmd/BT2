# Q5974: main (GIT_CONFIG_GLOBAL setup) — config race first sync under shared tmp

## Question
Can an unprivileged attacker who starts pushing before SetupExtraGitConfigs() finishes on first start, under a pod whose temp directory is shared with another container, reach a state where — in the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged — a fetch runs under partially applied configuration, breaking the invariant that no sync starts before configuration is complete and yielding sync performed without intended safety settings?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Starts pushing before SetupExtraGitConfigs() finishes on first start. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a fetch runs under partially applied configuration
- Invariant to test: no sync starts before configuration is complete
- Expected Immunefi impact: sync performed without intended safety settings (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: dump `git config list -z` under GIT_CONFIG_GLOBAL after the fixture sync and assert the effective keys equal the intended set
