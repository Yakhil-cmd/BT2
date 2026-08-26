# Q4282: main (GIT_CONFIG_GLOBAL setup) — nosystem scope under extra config

## Question
Under a deployment that also passes `--git-config`, an attacker relies on config sources GIT_CONFIG_NOSYSTEM does not cover (per-repo, per-worktree, includeIf). In the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged, can that mean attacker-influenced config is honoured despite the private global config, so that the invariant “only git-sync's own config layer is authoritative” no longer holds and the outcome is checkout-time command execution or transport redirection?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Relies on config sources GIT_CONFIG_NOSYSTEM does not cover (per-repo, per-worktree, includeIf). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: attacker-influenced config is honoured despite the private global config
- Invariant to test: only git-sync's own config layer is authoritative
- Expected Immunefi impact: checkout-time command execution or transport redirection (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
