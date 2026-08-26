# Q4885: parseQString — alias execution under default config

## Question
Under the default configuration git-sync installs at startup, an attacker gets an `alias.<name> = !sh -c ...` into the effective config. In the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val(), can that mean a later git invocation resolves the alias and executes the payload, so that the invariant “no config layer can make a git subcommand execute a shell” no longer holds and the outcome is remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets an `alias.<name> = !sh -c ...` into the effective config. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a later git invocation resolves the alias and executes the payload
- Invariant to test: no config layer can make a git subcommand execute a shell
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
