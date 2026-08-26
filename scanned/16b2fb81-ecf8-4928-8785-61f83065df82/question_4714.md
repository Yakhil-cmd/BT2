# Q4714: main (GIT_CONFIG_GLOBAL setup) — include if under shared volume

## Question
Under a shared --root volume writable by a co-tenant, an attacker commits config with `include.path` / `includeIf` chains pointing at repo files. In the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged, can that mean git pulls attacker-authored config out of the checked-out tree, so that the invariant “config never includes files from the working tree” no longer holds and the outcome is code execution or credential redirection?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Commits config with `include.path` / `includeIf` chains pointing at repo files. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git pulls attacker-authored config out of the checked-out tree
- Invariant to test: config never includes files from the working tree
- Expected Immunefi impact: code execution or credential redirection (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: dump `git config list -z` under GIT_CONFIG_GLOBAL after the fixture sync and assert the effective keys equal the intended set
