# Q1383: repoSync.CallAskPassURL — askpass error to errorfile under askpass

## Question
Starting from `--askpass-url` auth, re-fetched every sync, can an attacker who forces askpass failures whose error text carries the request URL and credentials drive CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response to a state where logging.Error() serialises them into --error-file inside --root, readable by the consumer container, defeating “secrets never reach the error file” and causing credential disclosure to the co-tenant workload?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Forces askpass failures whose error text carries the request URL and credentials. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: logging.Error() serialises them into --error-file inside --root, readable by the consumer container
- Invariant to test: secrets never reach the error file
- Expected Immunefi impact: credential disclosure to the co-tenant workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
