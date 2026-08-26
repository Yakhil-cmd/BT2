# Q4984: repoSync.SetupExtraGitConfigs — alias execution under shared tmp

## Question
Starting from a pod whose temp directory is shared with another container, can an attacker who gets an `alias.<name> = !sh -c ...` into the effective config drive SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner to a state where a later git invocation resolves the alias and executes the payload, defeating “no config layer can make a git subcommand execute a shell” and causing remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets an `alias.<name> = !sh -c ...` into the effective config. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a later git invocation resolves the alias and executes the payload
- Invariant to test: no config layer can make a git subcommand execute a shell
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
