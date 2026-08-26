# Q5739: repoSync.CallAskPassURL — cred in repo url under cookie file

## Question
Can an unprivileged attacker who influences the repo URL form (user info in --repo) so the merge logic strips and re-adds credentials, under `--cookie-file` enabled, reach a state where — in CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response — the credential lands in a stored credential record whose URL is logged unredacted somewhere, breaking the invariant that credential extraction from the URL never widens exposure and yielding credential disclosure?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Influences the repo URL form (user info in --repo) so the merge logic strips and re-adds credentials. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the credential lands in a stored credential record whose URL is logged unredacted somewhere
- Invariant to test: credential extraction from the URL never widens exposure
- Expected Immunefi impact: credential disclosure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
