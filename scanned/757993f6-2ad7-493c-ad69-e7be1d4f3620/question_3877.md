# Q3877: parseQString — scanner escape semantics under verbose

## Question
Under an elevated `--verbose` level, so config dumps are richer, an attacker supplies `\n`/`\t`/`\"` escape sequences whose expansion differs from git's own parser. In the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val(), can that mean the value git-sync intends and the value git stores diverge, so that the invariant “git-sync's parse matches git's parse exactly” no longer holds and the outcome is unintended git configuration silently in effect?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Supplies `\n`/`\t`/`\"` escape sequences whose expansion differs from git's own parser. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the value git-sync intends and the value git stores diverge
- Invariant to test: git-sync's parse matches git's parse exactly
- Expected Immunefi impact: unintended git configuration silently in effect (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: dump `git config list -z` under GIT_CONFIG_GLOBAL after the fixture sync and assert the effective keys equal the intended set
