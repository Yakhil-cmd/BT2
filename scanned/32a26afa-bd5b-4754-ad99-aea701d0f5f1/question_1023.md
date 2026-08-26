# Q1023: repoSync.CallAskPassURL — askpass redirect under password file

## Question
Under `--password-file`, re-read on every sync for rotation, an attacker gets the askpass endpoint to answer with a redirect or an error body containing secrets. In CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response, can that mean the response-status error path embeds the body in an error that is logged and written to the error file inside --root, so that the invariant “no auth-endpoint response body is ever written to a consumer-readable location” no longer holds and the outcome is credential disclosure into the shared volume?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Gets the askpass endpoint to answer with a redirect or an error body containing secrets. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the response-status error path embeds the body in an error that is logged and written to the error file inside --root
- Invariant to test: no auth-endpoint response body is ever written to a consumer-readable location
- Expected Immunefi impact: credential disclosure into the shared volume (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
