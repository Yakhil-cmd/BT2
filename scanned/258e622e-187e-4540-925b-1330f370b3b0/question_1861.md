# Q1861: parseQString — config value newline under http auth

## Question
Under HTTPS auth, where credential caching is live, an attacker supplies a value that reaches `git config --global <key> <val>` containing newlines or section-terminating characters. In the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val(), can that mean the written config file gains extra keys the operator never specified, so that the invariant “one config setting writes exactly one key” no longer holds and the outcome is silent injection of dangerous git config (transport helpers, aliases)?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Supplies a value that reaches `git config --global <key> <val>` containing newlines or section-terminating characters. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the written config file gains extra keys the operator never specified
- Invariant to test: one config setting writes exactly one key
- Expected Immunefi impact: silent injection of dangerous git config (transport helpers, aliases) (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
