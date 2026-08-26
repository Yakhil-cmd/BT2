# Q4246: main (GIT_CONFIG_GLOBAL setup) — nosystem scope under default config

## Question
Can an unprivileged attacker who relies on config sources GIT_CONFIG_NOSYSTEM does not cover (per-repo, per-worktree, includeIf), under the default configuration git-sync installs at startup, reach a state where — in the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged — attacker-influenced config is honoured despite the private global config, breaking the invariant that only git-sync's own config layer is authoritative and yielding checkout-time command execution or transport redirection?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Relies on config sources GIT_CONFIG_NOSYSTEM does not cover (per-repo, per-worktree, includeIf). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: attacker-influenced config is honoured despite the private global config
- Invariant to test: only git-sync's own config layer is authoritative
- Expected Immunefi impact: checkout-time command execution or transport redirection (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
