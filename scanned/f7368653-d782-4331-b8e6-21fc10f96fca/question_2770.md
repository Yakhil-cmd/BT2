# Q2770: main (GIT_CONFIG_GLOBAL setup) — protocol allow under shared volume

## Question
Starting from a shared --root volume writable by a co-tenant, can an attacker who gets `protocol.*.allow=always` (or ext transport enabled) into the effective config drive the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged to a state where the ext/file transports that git blocks by default become usable from `.gitmodules`, defeating “dangerous transports remain disabled for all repo-supplied URLs” and causing remote code execution via a submodule transport helper?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets `protocol.*.allow=always` (or ext transport enabled) into the effective config. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the ext/file transports that git blocks by default become usable from `.gitmodules`
- Invariant to test: dangerous transports remain disabled for all repo-supplied URLs
- Expected Immunefi impact: remote code execution via a submodule transport helper (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: dump `git config list -z` under GIT_CONFIG_GLOBAL after the fixture sync and assert the effective keys equal the intended set
