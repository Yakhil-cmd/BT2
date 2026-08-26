# Q3382: main (GIT_CONFIG_GLOBAL setup) — scanner goroutine leak under shared tmp

## Question
Can an unprivileged attacker who supplies very large or pathological config strings, under a pod whose temp directory is shared with another container, reach a state where — in the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged — the feeding goroutine and buffered channel in parseGitConfigs() retain memory per call, breaking the invariant that config parsing is O(n) with no retained state and yielding memory growth in a long-lived sidecar?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Supplies very large or pathological config strings. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the feeding goroutine and buffered channel in parseGitConfigs() retain memory per call
- Invariant to test: config parsing is O(n) with no retained state
- Expected Immunefi impact: memory growth in a long-lived sidecar (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
