# Q2518: main (GIT_CONFIG_GLOBAL setup) — url insteadof under http auth

## Question
Can an unprivileged attacker who gets a `url.<base>.insteadOf` rewrite into the effective config through any layer, under HTTPS auth, where credential caching is live, reach a state where — in the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged — all later fetches, including submodules, are silently redirected while logs still show the original URL, breaking the invariant that no config layer can rewrite the configured remote URL and yielding unauthorized content published plus credential disclosure to the rewritten host?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets a `url.<base>.insteadOf` rewrite into the effective config through any layer. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: all later fetches, including submodules, are silently redirected while logs still show the original URL
- Invariant to test: no config layer can rewrite the configured remote URL
- Expected Immunefi impact: unauthorized content published plus credential disclosure to the rewritten host (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
