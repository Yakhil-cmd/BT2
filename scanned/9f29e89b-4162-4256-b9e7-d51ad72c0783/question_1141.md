# Q1141: parseQString — gc autodetach flip under shared volume

## Question
Under a shared --root volume writable by a co-tenant, an attacker gets `gc.autoDetach` re-enabled through another config layer. In the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val(), can that mean gc detaches and races the next fetch, corrupting the repo, so that the invariant “gc never detaches” no longer holds and the outcome is repo corruption forcing a full wipe-and-refetch loop?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets `gc.autoDetach` re-enabled through another config layer. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: gc detaches and races the next fetch, corrupting the repo
- Invariant to test: gc never detaches
- Expected Immunefi impact: repo corruption forcing a full wipe-and-refetch loop (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: dump `git config list -z` under GIT_CONFIG_GLOBAL after the fixture sync and assert the effective keys equal the intended set
