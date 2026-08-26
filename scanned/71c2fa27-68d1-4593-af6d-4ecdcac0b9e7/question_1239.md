# Q1239: repoSync.CallAskPassURL — askpass redirect under error file

## Question
Starting from `--error-file` inside --root, readable by the consumer, can an attacker who gets the askpass endpoint to answer with a redirect or an error body containing secrets drive CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response to a state where the response-status error path embeds the body in an error that is logged and written to the error file inside --root, defeating “no auth-endpoint response body is ever written to a consumer-readable location” and causing credential disclosure into the shared volume?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Gets the askpass endpoint to answer with a redirect or an error body containing secrets. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the response-status error path embeds the body in an error that is logged and written to the error file inside --root
- Invariant to test: no auth-endpoint response body is ever written to a consumer-readable location
- Expected Immunefi impact: credential disclosure into the shared volume (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
