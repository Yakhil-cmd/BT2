# Q2698: main (GIT_CONFIG_GLOBAL setup) — protocol allow under extra config add

## Question
Under a deployment that also passes `--git-config-add` (repeatable), an attacker gets `protocol.*.allow=always` (or ext transport enabled) into the effective config. In the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged, can that mean the ext/file transports that git blocks by default become usable from `.gitmodules`, so that the invariant “dangerous transports remain disabled for all repo-supplied URLs” no longer holds and the outcome is remote code execution via a submodule transport helper?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets `protocol.*.allow=always` (or ext transport enabled) into the effective config. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the ext/file transports that git blocks by default become usable from `.gitmodules`
- Invariant to test: dangerous transports remain disabled for all repo-supplied URLs
- Expected Immunefi impact: remote code execution via a submodule transport helper (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
