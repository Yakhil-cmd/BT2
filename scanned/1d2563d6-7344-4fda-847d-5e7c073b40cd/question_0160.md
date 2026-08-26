# Q0160: repoSync.SetupExtraGitConfigs — repo supplied config precedence under shared volume

## Question
Under a shared --root volume writable by a co-tenant, an attacker commits repository-local config (a checked-in `.git` directory, or a submodule's config) that git reads for worktree operations. In SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner, can that mean repo-level config overrides the safety-relevant globals git-sync installed, so that the invariant “git-sync's security-relevant git config cannot be overridden by repo content” no longer holds and the outcome is checkout-time command execution or credential redirection?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Commits repository-local config (a checked-in `.git` directory, or a submodule's config) that git reads for worktree operations. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: repo-level config overrides the safety-relevant globals git-sync installed
- Invariant to test: git-sync's security-relevant git config cannot be overridden by repo content
- Expected Immunefi impact: checkout-time command execution or credential redirection (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
