# Q5101: parseQString — alias execution under http auth

## Question
Starting from HTTPS auth, where credential caching is live, can an attacker who gets an `alias.<name> = !sh -c ...` into the effective config drive the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val() to a state where a later git invocation resolves the alias and executes the payload, defeating “no config layer can make a git subcommand execute a shell” and causing remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets an `alias.<name> = !sh -c ...` into the effective config. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a later git invocation resolves the alias and executes the payload
- Invariant to test: no config layer can make a git subcommand execute a shell
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
