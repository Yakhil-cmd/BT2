# Q0789: repoSync.SetupGitSSH — askpass response injection under github app

## Question
Can an unprivileged attacker who controls or influences the askpass response body (attacker-run endpoint reached via redirect, or response reflection), under GitHub App auth with `--github-app-*` flags, reach a state where — in SetupGitSSH()'s `$GIT_SSH_COMMAND` string building, SetupCookieFile(), and the redaction helpers redactURL()/logSafeFlags() — the naive newline/`=` split lets an injected `password=` line or embedded newline overwrite the real credential or inject extra credential fields, breaking the invariant that the askpass response is parsed as a strict, complete credential record and yielding credential substitution: git-sync authenticates to, or leaks to, an attacker-chosen target?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupGitSSH / SetupCookieFile / redactURL / logSafeFlags`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Controls or influences the askpass response body (attacker-run endpoint reached via redirect, or response reflection). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the naive newline/`=` split lets an injected `password=` line or embedded newline overwrite the real credential or inject extra credential fields
- Invariant to test: the askpass response is parsed as a strict, complete credential record
- Expected Immunefi impact: credential substitution: git-sync authenticates to, or leaks to, an attacker-chosen target (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
