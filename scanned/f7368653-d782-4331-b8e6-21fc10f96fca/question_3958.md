# Q3958: main (GIT_CONFIG_GLOBAL setup) — config list log leak under extra config

## Question
Can an unprivileged attacker who gets a secret-bearing config value into the effective config, under a deployment that also passes `--git-config`, reach a state where — in the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged — the `git config list -z` dump is logged at V(0) and written to the error file on failure, breaking the invariant that config dumps never include credential material and yielding credential disclosure via logs and the shared-volume error file?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets a secret-bearing config value into the effective config. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `git config list -z` dump is logged at V(0) and written to the error file on failure
- Invariant to test: config dumps never include credential material
- Expected Immunefi impact: credential disclosure via logs and the shared-volume error file (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
