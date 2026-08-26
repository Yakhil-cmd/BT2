# Q1258: main (GIT_CONFIG_GLOBAL setup) — gc autodetach flip under gc always

## Question
Under `--git-gc=always`, so maintenance config matters every period, an attacker gets `gc.autoDetach` re-enabled through another config layer. In the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged, can that mean gc detaches and races the next fetch, corrupting the repo, so that the invariant “gc never detaches” no longer holds and the outcome is repo corruption forcing a full wipe-and-refetch loop?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets `gc.autoDetach` re-enabled through another config layer. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: gc detaches and races the next fetch, corrupting the repo
- Invariant to test: gc never detaches
- Expected Immunefi impact: repo corruption forcing a full wipe-and-refetch loop (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
