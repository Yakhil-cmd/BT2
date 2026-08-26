# Q4875: repoSync.CallAskPassURL — credential append order under http basic

## Question
Can an unprivileged attacker who relies on the precedence between --credential entries and the --repo-derived credential, under HTTPS auth with `--username` and `$GITSYNC_PASSWORD`, reach a state where — in CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response — the wrong credential is matched for the fetch and a credential is offered to an unintended URL, breaking the invariant that credential precedence is deterministic and scoped and yielding credential disclosure to an unintended host?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Relies on the precedence between --credential entries and the --repo-derived credential. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the wrong credential is matched for the fetch and a credential is offered to an unintended URL
- Invariant to test: credential precedence is deterministic and scoped
- Expected Immunefi impact: credential disclosure to an unintended host (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
