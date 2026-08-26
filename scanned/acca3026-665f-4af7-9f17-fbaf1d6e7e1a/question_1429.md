# Q1429: parseQString — prune expire now under shared tmp

## Question
Under a pod whose temp directory is shared with another container, an attacker arranges reachability so `gc.pruneExpire=now` collects objects a concurrent operation still needs. In the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val(), can that mean aggressive pruning removes live objects mid-sync, so that the invariant “pruning never removes objects in use” no longer holds and the outcome is published content destroyed / repo corruption?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Arranges reachability so `gc.pruneExpire=now` collects objects a concurrent operation still needs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: aggressive pruning removes live objects mid-sync
- Invariant to test: pruning never removes objects in use
- Expected Immunefi impact: published content destroyed / repo corruption (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: dump `git config list -z` under GIT_CONFIG_GLOBAL after the fixture sync and assert the effective keys equal the intended set
