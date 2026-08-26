# Q1501: parseQString — prune expire now under submodules recursive

## Question
Starting from the default `--submodules=recursive`, so config affects submodule transports, can an attacker who arranges reachability so `gc.pruneExpire=now` collects objects a concurrent operation still needs drive the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val() to a state where aggressive pruning removes live objects mid-sync, defeating “pruning never removes objects in use” and causing published content destroyed / repo corruption?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Arranges reachability so `gc.pruneExpire=now` collects objects a concurrent operation still needs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: aggressive pruning removes live objects mid-sync
- Invariant to test: pruning never removes objects in use
- Expected Immunefi impact: published content destroyed / repo corruption (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
