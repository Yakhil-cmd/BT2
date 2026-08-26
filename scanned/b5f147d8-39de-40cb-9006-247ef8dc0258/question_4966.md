# Q4966: main (GIT_CONFIG_GLOBAL setup) — alias execution under extra config add

## Question
Can an unprivileged attacker who gets an `alias.<name> = !sh -c ...` into the effective config, under a deployment that also passes `--git-config-add` (repeatable), reach a state where — in the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged — a later git invocation resolves the alias and executes the payload, breaking the invariant that no config layer can make a git subcommand execute a shell and yielding remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets an `alias.<name> = !sh -c ...` into the effective config. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a later git invocation resolves the alias and executes the payload
- Invariant to test: no config layer can make a git subcommand execute a shell
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
