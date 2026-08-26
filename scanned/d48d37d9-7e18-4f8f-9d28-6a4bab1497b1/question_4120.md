# Q4120: repoSync.SetupExtraGitConfigs — config list log leak under http auth

## Question
Starting from HTTPS auth, where credential caching is live, can an attacker who gets a secret-bearing config value into the effective config drive SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner to a state where the `git config list -z` dump is logged at V(0) and written to the error file on failure, defeating “config dumps never include credential material” and causing credential disclosure via logs and the shared-volume error file?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets a secret-bearing config value into the effective config. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `git config list -z` dump is logged at V(0) and written to the error file on failure
- Invariant to test: config dumps never include credential material
- Expected Immunefi impact: credential disclosure via logs and the shared-volume error file (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
