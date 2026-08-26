# Q0583: repoSync.SetupDefaultGitConfigs — safe directory bypass under gc always

## Question
Can an unprivileged attacker who exploits the ownership mismatch between the git-sync UID and volume ownership on a shared volume, under `--git-gc=always`, so maintenance config matters every period, reach a state where — in SetupDefaultGitConfigs(): gc.autoDetach=false, gc.pruneExpire=now, credential.helper=cache, core.askPass=true written to the private GIT_CONFIG_GLOBAL — git either refuses to operate (wedge) or is made to trust a directory a co-tenant can write, breaking the invariant that repository trust decisions are independent of co-tenant-writable state and yielding code execution via a co-tenant-planted config, or permanent sync failure?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Exploits the ownership mismatch between the git-sync UID and volume ownership on a shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git either refuses to operate (wedge) or is made to trust a directory a co-tenant can write
- Invariant to test: repository trust decisions are independent of co-tenant-writable state
- Expected Immunefi impact: code execution via a co-tenant-planted config, or permanent sync failure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
