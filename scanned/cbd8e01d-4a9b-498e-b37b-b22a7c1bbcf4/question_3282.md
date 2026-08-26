# Q3282: repoSync.StoreCredentials — redacturl parse gap under password file

## Question
Starting from `--password-file`, re-read on every sync for rotation, can an attacker who supplies repo-adjacent URLs that `url.Parse` fails on (scp-like `user:pass@host:path`) into any logged path drive StoreCredentials(): the `url=/username=/password=` blob piped into `git credential approve` to a state where redactURL() returns the string unchanged, printing the password into logs and the error file, defeating “every logged URL is redacted regardless of form” and causing credential disclosure via logs readable by the co-tenant?

## Target
- File/function: [main.go](main.go) — `repoSync.StoreCredentials`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Supplies repo-adjacent URLs that `url.Parse` fails on (scp-like `user:pass@host:path`) into any logged path. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: redactURL() returns the string unchanged, printing the password into logs and the error file
- Invariant to test: every logged URL is redacted regardless of form
- Expected Immunefi impact: credential disclosure via logs readable by the co-tenant (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
