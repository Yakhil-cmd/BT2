# Q3858: repoSync.StoreCredentials — logsafeflags gap under verbose

## Question
Starting from an elevated `--verbose` level used for debugging in production, can an attacker who relies on a code path where a secret-bearing flag value is logged without going through the password/repo/credential special cases drive StoreCredentials(): the `url=/username=/password=` blob piped into `git credential approve` to a state where the secret appears in the startup log and, on error, in --error-file, defeating “no flag value containing a secret is ever printed” and causing credential disclosure?

## Target
- File/function: [main.go](main.go) — `repoSync.StoreCredentials`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Relies on a code path where a secret-bearing flag value is logged without going through the password/repo/credential special cases. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the secret appears in the startup log and, on error, in --error-file
- Invariant to test: no flag value containing a secret is ever printed
- Expected Immunefi impact: credential disclosure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
