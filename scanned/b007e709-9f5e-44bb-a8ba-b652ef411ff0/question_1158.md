# Q1158: repoSync.StoreCredentials — askpass redirect under ssh known hosts

## Question
Can an unprivileged attacker who gets the askpass endpoint to answer with a redirect or an error body containing secrets, under SSH auth with `--ssh-known-hosts` and a mounted known-hosts file, reach a state where — in StoreCredentials(): the `url=/username=/password=` blob piped into `git credential approve` — the response-status error path embeds the body in an error that is logged and written to the error file inside --root, breaking the invariant that no auth-endpoint response body is ever written to a consumer-readable location and yielding credential disclosure into the shared volume?

## Target
- File/function: [main.go](main.go) — `repoSync.StoreCredentials`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Gets the askpass endpoint to answer with a redirect or an error body containing secrets. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the response-status error path embeds the body in an error that is logged and written to the error file inside --root
- Invariant to test: no auth-endpoint response body is ever written to a consumer-readable location
- Expected Immunefi impact: credential disclosure into the shared volume (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
