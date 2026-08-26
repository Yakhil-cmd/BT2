# Q3112: repoSync.SetupExtraGitConfigs — scanner unterminated quote under submodules recursive

## Question
Starting from the default `--submodules=recursive`, so config affects submodule transports, can an attacker who supplies config text with an unterminated quote or a trailing escape drive SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner to a state where parseQString()/unescape() consume from a closed channel and return a partial or wrong pair, or block, defeating “the scanner terminates deterministically on any input” and causing wrong git config applied, or a hang before the first sync?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Supplies config text with an unterminated quote or a trailing escape. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: parseQString()/unescape() consume from a closed channel and return a partial or wrong pair, or block
- Invariant to test: the scanner terminates deterministically on any input
- Expected Immunefi impact: wrong git config applied, or a hang before the first sync (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: dump `git config list -z` under GIT_CONFIG_GLOBAL after the fixture sync and assert the effective keys equal the intended set
