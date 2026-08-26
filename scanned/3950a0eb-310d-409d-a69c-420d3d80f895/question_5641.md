# Q5641: parseQString — tempfile config predict under shared tmp

## Question
Does the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val() stay safe when an attacker targets the `git-sync.gitconfig.*` tempfile in the shared temp directory in a pod whose temp directory is shared with another container — or can a co-tenant able to write that directory replaces the global config git-sync just created, violating “the private config file cannot be replaced by another process” and producing full control of git behaviour, i.e. code execution?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Targets the `git-sync.gitconfig.*` tempfile in the shared temp directory. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a co-tenant able to write that directory replaces the global config git-sync just created
- Invariant to test: the private config file cannot be replaced by another process
- Expected Immunefi impact: full control of git behaviour, i.e. code execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
