# Q0277: parseQString — repo supplied config precedence under gc always

## Question
Under `--git-gc=always`, so maintenance config matters every period, an attacker commits repository-local config (a checked-in `.git` directory, or a submodule's config) that git reads for worktree operations. In the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val(), can that mean repo-level config overrides the safety-relevant globals git-sync installed, so that the invariant “git-sync's security-relevant git config cannot be overridden by repo content” no longer holds and the outcome is checkout-time command execution or credential redirection?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Commits repository-local config (a checked-in `.git` directory, or a submodule's config) that git reads for worktree operations. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: repo-level config overrides the safety-relevant globals git-sync installed
- Invariant to test: git-sync's security-relevant git config cannot be overridden by repo content
- Expected Immunefi impact: checkout-time command execution or credential redirection (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: dump `git config list -z` under GIT_CONFIG_GLOBAL after the fixture sync and assert the effective keys equal the intended set
