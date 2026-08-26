# Q5569: parseQString — tempfile config predict under extra config

## Question
Can an unprivileged attacker who targets the `git-sync.gitconfig.*` tempfile in the shared temp directory, under a deployment that also passes `--git-config`, reach a state where — in the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val() — a co-tenant able to write that directory replaces the global config git-sync just created, breaking the invariant that the private config file cannot be replaced by another process and yielding full control of git behaviour, i.e. code execution?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Targets the `git-sync.gitconfig.*` tempfile in the shared temp directory. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a co-tenant able to write that directory replaces the global config git-sync just created
- Invariant to test: the private config file cannot be replaced by another process
- Expected Immunefi impact: full control of git behaviour, i.e. code execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
