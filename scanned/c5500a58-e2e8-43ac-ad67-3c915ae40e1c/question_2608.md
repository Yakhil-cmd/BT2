# Q2608: repoSync.SetupExtraGitConfigs — protocol allow under default config

## Question
Under the default configuration git-sync installs at startup, an attacker gets `protocol.*.allow=always` (or ext transport enabled) into the effective config. In SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner, can that mean the ext/file transports that git blocks by default become usable from `.gitmodules`, so that the invariant “dangerous transports remain disabled for all repo-supplied URLs” no longer holds and the outcome is remote code execution via a submodule transport helper?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets `protocol.*.allow=always` (or ext transport enabled) into the effective config. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the ext/file transports that git blocks by default become usable from `.gitmodules`
- Invariant to test: dangerous transports remain disabled for all repo-supplied URLs
- Expected Immunefi impact: remote code execution via a submodule transport helper (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: dump `git config list -z` under GIT_CONFIG_GLOBAL after the fixture sync and assert the effective keys equal the intended set
