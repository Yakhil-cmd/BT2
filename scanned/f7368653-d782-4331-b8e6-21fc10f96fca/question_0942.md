# Q0942: repoSync.StoreCredentials — askpass response injection under verbose

## Question
Does StoreCredentials(): the `url=/username=/password=` blob piped into `git credential approve` stay safe when an attacker controls or influences the askpass response body (attacker-run endpoint reached via redirect, or response reflection) in an elevated `--verbose` level used for debugging in production — or can the naive newline/`=` split lets an injected `password=` line or embedded newline overwrite the real credential or inject extra credential fields, violating “the askpass response is parsed as a strict, complete credential record” and producing credential substitution: git-sync authenticates to, or leaks to, an attacker-chosen target?

## Target
- File/function: [main.go](main.go) — `repoSync.StoreCredentials`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Controls or influences the askpass response body (attacker-run endpoint reached via redirect, or response reflection). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the naive newline/`=` split lets an injected `password=` line or embedded newline overwrite the real credential or inject extra credential fields
- Invariant to test: the askpass response is parsed as a strict, complete credential record
- Expected Immunefi impact: credential substitution: git-sync authenticates to, or leaks to, an attacker-chosen target (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
