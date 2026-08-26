# Q2464: repoSync.SetupExtraGitConfigs — url insteadof under submodules recursive

## Question
Under the default `--submodules=recursive`, so config affects submodule transports, an attacker gets a `url.<base>.insteadOf` rewrite into the effective config through any layer. In SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner, can that mean all later fetches, including submodules, are silently redirected while logs still show the original URL, so that the invariant “no config layer can rewrite the configured remote URL” no longer holds and the outcome is unauthorized content published plus credential disclosure to the rewritten host?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets a `url.<base>.insteadOf` rewrite into the effective config through any layer. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: all later fetches, including submodules, are silently redirected while logs still show the original URL
- Invariant to test: no config layer can rewrite the configured remote URL
- Expected Immunefi impact: unauthorized content published plus credential disclosure to the rewritten host (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
