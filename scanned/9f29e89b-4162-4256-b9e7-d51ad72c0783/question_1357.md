# Q1357: parseQString — prune expire now under extra config

## Question
Starting from a deployment that also passes `--git-config`, can an attacker who arranges reachability so `gc.pruneExpire=now` collects objects a concurrent operation still needs drive the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val() to a state where aggressive pruning removes live objects mid-sync, defeating “pruning never removes objects in use” and causing published content destroyed / repo corruption?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Arranges reachability so `gc.pruneExpire=now` collects objects a concurrent operation still needs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: aggressive pruning removes live objects mid-sync
- Invariant to test: pruning never removes objects in use
- Expected Immunefi impact: published content destroyed / repo corruption (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
