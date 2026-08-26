# Q3013: parseQString — scanner unterminated quote under extra config add

## Question
Under a deployment that also passes `--git-config-add` (repeatable), an attacker supplies config text with an unterminated quote or a trailing escape. In the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val(), can that mean parseQString()/unescape() consume from a closed channel and return a partial or wrong pair, or block, so that the invariant “the scanner terminates deterministically on any input” no longer holds and the outcome is wrong git config applied, or a hang before the first sync?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Supplies config text with an unterminated quote or a trailing escape. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: parseQString()/unescape() consume from a closed channel and return a partial or wrong pair, or block
- Invariant to test: the scanner terminates deterministically on any input
- Expected Immunefi impact: wrong git config applied, or a hang before the first sync (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
