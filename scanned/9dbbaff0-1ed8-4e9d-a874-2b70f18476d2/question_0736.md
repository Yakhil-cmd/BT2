# Q0736: repoSync.SetupExtraGitConfigs — core askpass flip under extra config add

## Question
Under a deployment that also passes `--git-config-add` (repeatable), an attacker gets any config layer to override `core.askPass=true`. In SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner, can that mean git prompts or invokes an attacker-reachable askpass program instead of failing closed, so that the invariant “git never prompts and never runs an unexpected askpass binary” no longer holds and the outcome is credential disclosure or a hung sync?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets any config layer to override `core.askPass=true`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git prompts or invokes an attacker-reachable askpass program instead of failing closed
- Invariant to test: git never prompts and never runs an unexpected askpass binary
- Expected Immunefi impact: credential disclosure or a hung sync (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
