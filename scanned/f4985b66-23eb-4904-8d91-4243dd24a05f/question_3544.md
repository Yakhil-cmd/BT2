# Q3544: repoSync.SetupExtraGitConfigs — scanner goroutine leak under verbose

## Question
Starting from an elevated `--verbose` level, so config dumps are richer, can an attacker who supplies very large or pathological config strings drive SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner to a state where the feeding goroutine and buffered channel in parseGitConfigs() retain memory per call, defeating “config parsing is O(n) with no retained state” and causing memory growth in a long-lived sidecar?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Supplies very large or pathological config strings. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the feeding goroutine and buffered channel in parseGitConfigs() retain memory per call
- Invariant to test: config parsing is O(n) with no retained state
- Expected Immunefi impact: memory growth in a long-lived sidecar (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
