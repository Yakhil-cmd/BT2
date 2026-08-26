# Q2869: parseQString — protocol allow under gc always

## Question
Under `--git-gc=always`, so maintenance config matters every period, an attacker gets `protocol.*.allow=always` (or ext transport enabled) into the effective config. In the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val(), can that mean the ext/file transports that git blocks by default become usable from `.gitmodules`, so that the invariant “dangerous transports remain disabled for all repo-supplied URLs” no longer holds and the outcome is remote code execution via a submodule transport helper?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets `protocol.*.allow=always` (or ext transport enabled) into the effective config. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the ext/file transports that git blocks by default become usable from `.gitmodules`
- Invariant to test: dangerous transports remain disabled for all repo-supplied URLs
- Expected Immunefi impact: remote code execution via a submodule transport helper (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
