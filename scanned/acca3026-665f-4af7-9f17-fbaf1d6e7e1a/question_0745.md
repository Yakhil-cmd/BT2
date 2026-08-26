# Q0745: parseQString — core askpass flip under extra config add

## Question
Does the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val() stay safe when an attacker gets any config layer to override `core.askPass=true` in a deployment that also passes `--git-config-add` (repeatable) — or can git prompts or invokes an attacker-reachable askpass program instead of failing closed, violating “git never prompts and never runs an unexpected askpass binary” and producing credential disclosure or a hung sync?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets any config layer to override `core.askPass=true`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git prompts or invokes an attacker-reachable askpass program instead of failing closed
- Invariant to test: git never prompts and never runs an unexpected askpass binary
- Expected Immunefi impact: credential disclosure or a hung sync (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: dump `git config list -z` under GIT_CONFIG_GLOBAL after the fixture sync and assert the effective keys equal the intended set
