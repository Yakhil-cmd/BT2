# Q1519: repoSync.SetupDefaultGitConfigs — prune expire now under http auth

## Question
Does SetupDefaultGitConfigs(): gc.autoDetach=false, gc.pruneExpire=now, credential.helper=cache, core.askPass=true written to the private GIT_CONFIG_GLOBAL stay safe when an attacker arranges reachability so `gc.pruneExpire=now` collects objects a concurrent operation still needs in HTTPS auth, where credential caching is live — or can aggressive pruning removes live objects mid-sync, violating “pruning never removes objects in use” and producing published content destroyed / repo corruption?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Arranges reachability so `gc.pruneExpire=now` collects objects a concurrent operation still needs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: aggressive pruning removes live objects mid-sync
- Invariant to test: pruning never removes objects in use
- Expected Immunefi impact: published content destroyed / repo corruption (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
