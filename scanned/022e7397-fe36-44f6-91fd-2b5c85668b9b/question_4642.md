# Q4642: main (GIT_CONFIG_GLOBAL setup) — include if under extra config add

## Question
Starting from a deployment that also passes `--git-config-add` (repeatable), can an attacker who commits config with `include.path` / `includeIf` chains pointing at repo files drive the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged to a state where git pulls attacker-authored config out of the checked-out tree, defeating “config never includes files from the working tree” and causing code execution or credential redirection?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Commits config with `include.path` / `includeIf` chains pointing at repo files. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git pulls attacker-authored config out of the checked-out tree
- Invariant to test: config never includes files from the working tree
- Expected Immunefi impact: code execution or credential redirection (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
