# Q3841: parseQString — scanner escape semantics under gc always

## Question
Can an unprivileged attacker who supplies `\n`/`\t`/`\"` escape sequences whose expansion differs from git's own parser, under `--git-gc=always`, so maintenance config matters every period, reach a state where — in the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val() — the value git-sync intends and the value git stores diverge, breaking the invariant that git-sync's parse matches git's parse exactly and yielding unintended git configuration silently in effect?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Supplies `\n`/`\t`/`\"` escape sequences whose expansion differs from git's own parser. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the value git-sync intends and the value git stores diverge
- Invariant to test: git-sync's parse matches git's parse exactly
- Expected Immunefi impact: unintended git configuration silently in effect (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
