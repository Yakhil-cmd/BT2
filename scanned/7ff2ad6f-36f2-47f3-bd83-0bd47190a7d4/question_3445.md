# Q3445: parseQString — scanner goroutine leak under submodules recursive

## Question
Under the default `--submodules=recursive`, so config affects submodule transports, an attacker supplies very large or pathological config strings. In the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val(), can that mean the feeding goroutine and buffered channel in parseGitConfigs() retain memory per call, so that the invariant “config parsing is O(n) with no retained state” no longer holds and the outcome is memory growth in a long-lived sidecar?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Supplies very large or pathological config strings. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the feeding goroutine and buffered channel in parseGitConfigs() retain memory per call
- Invariant to test: config parsing is O(n) with no retained state
- Expected Immunefi impact: memory growth in a long-lived sidecar (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
