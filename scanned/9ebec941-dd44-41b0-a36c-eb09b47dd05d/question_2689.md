# Q2689: parseQString — protocol allow under extra config add

## Question
Can an unprivileged attacker who gets `protocol.*.allow=always` (or ext transport enabled) into the effective config, under a deployment that also passes `--git-config-add` (repeatable), reach a state where — in the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val() — the ext/file transports that git blocks by default become usable from `.gitmodules`, breaking the invariant that dangerous transports remain disabled for all repo-supplied URLs and yielding remote code execution via a submodule transport helper?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets `protocol.*.allow=always` (or ext transport enabled) into the effective config. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the ext/file transports that git blocks by default become usable from `.gitmodules`
- Invariant to test: dangerous transports remain disabled for all repo-supplied URLs
- Expected Immunefi impact: remote code execution via a submodule transport helper (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: dump `git config list -z` under GIT_CONFIG_GLOBAL after the fixture sync and assert the effective keys equal the intended set
