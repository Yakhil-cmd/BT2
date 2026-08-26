# Q4876: repoSync.SetupExtraGitConfigs — alias execution under default config

## Question
Can an unprivileged attacker who gets an `alias.<name> = !sh -c ...` into the effective config, under the default configuration git-sync installs at startup, reach a state where — in SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner — a later git invocation resolves the alias and executes the payload, breaking the invariant that no config layer can make a git subcommand execute a shell and yielding remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets an `alias.<name> = !sh -c ...` into the effective config. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a later git invocation resolves the alias and executes the payload
- Invariant to test: no config layer can make a git subcommand execute a shell
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
