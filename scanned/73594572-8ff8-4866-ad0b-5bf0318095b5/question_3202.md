# Q3202: main (GIT_CONFIG_GLOBAL setup) — scanner unterminated quote under gc always

## Question
Starting from `--git-gc=always`, so maintenance config matters every period, can an attacker who supplies config text with an unterminated quote or a trailing escape drive the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged to a state where parseQString()/unescape() consume from a closed channel and return a partial or wrong pair, or block, defeating “the scanner terminates deterministically on any input” and causing wrong git config applied, or a hang before the first sync?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Supplies config text with an unterminated quote or a trailing escape. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: parseQString()/unescape() consume from a closed channel and return a partial or wrong pair, or block
- Invariant to test: the scanner terminates deterministically on any input
- Expected Immunefi impact: wrong git config applied, or a hang before the first sync (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
