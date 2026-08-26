# Q0601: parseQString — safe directory bypass under gc always

## Question
Does the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val() stay safe when an attacker exploits the ownership mismatch between the git-sync UID and volume ownership on a shared volume in `--git-gc=always`, so maintenance config matters every period — or can git either refuses to operate (wedge) or is made to trust a directory a co-tenant can write, violating “repository trust decisions are independent of co-tenant-writable state” and producing code execution via a co-tenant-planted config, or permanent sync failure?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Exploits the ownership mismatch between the git-sync UID and volume ownership on a shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git either refuses to operate (wedge) or is made to trust a directory a co-tenant can write
- Invariant to test: repository trust decisions are independent of co-tenant-writable state
- Expected Immunefi impact: code execution via a co-tenant-planted config, or permanent sync failure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
