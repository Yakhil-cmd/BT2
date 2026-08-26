# Q2941: parseQString — scanner unterminated quote under default config

## Question
Starting from the default configuration git-sync installs at startup, can an attacker who supplies config text with an unterminated quote or a trailing escape drive the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val() to a state where parseQString()/unescape() consume from a closed channel and return a partial or wrong pair, or block, defeating “the scanner terminates deterministically on any input” and causing wrong git config applied, or a hang before the first sync?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Supplies config text with an unterminated quote or a trailing escape. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: parseQString()/unescape() consume from a closed channel and return a partial or wrong pair, or block
- Invariant to test: the scanner terminates deterministically on any input
- Expected Immunefi impact: wrong git config applied, or a hang before the first sync (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
