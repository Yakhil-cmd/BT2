# Q3291: repoSync.CallAskPassURL — redacturl parse gap under password file

## Question
Can an unprivileged attacker who supplies repo-adjacent URLs that `url.Parse` fails on (scp-like `user:pass@host:path`) into any logged path, under `--password-file`, re-read on every sync for rotation, reach a state where — in CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response — redactURL() returns the string unchanged, printing the password into logs and the error file, breaking the invariant that every logged URL is redacted regardless of form and yielding credential disclosure via logs readable by the co-tenant?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Supplies repo-adjacent URLs that `url.Parse` fails on (scp-like `user:pass@host:path`) into any logged path. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: redactURL() returns the string unchanged, printing the password into logs and the error file
- Invariant to test: every logged URL is redacted regardless of form
- Expected Immunefi impact: credential disclosure via logs readable by the co-tenant (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
