# Q2788: repoSync.SetupExtraGitConfigs — protocol allow under submodules recursive

## Question
Does SetupExtraGitConfigs()/parseGitConfigs() and the hand-rolled quoted key/value scanner stay safe when an attacker gets `protocol.*.allow=always` (or ext transport enabled) into the effective config in the default `--submodules=recursive`, so config affects submodule transports — or can the ext/file transports that git blocks by default become usable from `.gitmodules`, violating “dangerous transports remain disabled for all repo-supplied URLs” and producing remote code execution via a submodule transport helper?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupExtraGitConfigs / parseGitConfigs`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets `protocol.*.allow=always` (or ext transport enabled) into the effective config. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the ext/file transports that git blocks by default become usable from `.gitmodules`
- Invariant to test: dangerous transports remain disabled for all repo-supplied URLs
- Expected Immunefi impact: remote code execution via a submodule transport helper (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
