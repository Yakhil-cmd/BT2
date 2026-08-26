# Q4417: parseQString — nosystem scope under submodules recursive

## Question
Can an unprivileged attacker who relies on config sources GIT_CONFIG_NOSYSTEM does not cover (per-repo, per-worktree, includeIf), under the default `--submodules=recursive`, so config affects submodule transports, reach a state where — in the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val() — attacker-influenced config is honoured despite the private global config, breaking the invariant that only git-sync's own config layer is authoritative and yielding checkout-time command execution or transport redirection?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Relies on config sources GIT_CONFIG_NOSYSTEM does not cover (per-repo, per-worktree, includeIf). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: attacker-influenced config is honoured despite the private global config
- Invariant to test: only git-sync's own config layer is authoritative
- Expected Immunefi impact: checkout-time command execution or transport redirection (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
