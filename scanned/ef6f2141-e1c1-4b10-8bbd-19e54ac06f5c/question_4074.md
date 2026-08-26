# Q4074: repoSync.StoreCredentials — md5 cred log under ssh known hosts

## Question
Under SSH auth with `--ssh-known-hosts` and a mounted known-hosts file, an attacker gets verbosity raised or an error path that includes the V(9) credential md5 line. In StoreCredentials(): the `url=/username=/password=` blob piped into `git credential approve`, can that mean md5 of username and password land in logs, enabling offline cracking of weak credentials, so that the invariant “no derivative of a credential is logged” no longer holds and the outcome is credential disclosure via log-derived hashes?

## Target
- File/function: [main.go](main.go) — `repoSync.StoreCredentials`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Gets verbosity raised or an error path that includes the V(9) credential md5 line. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: md5 of username and password land in logs, enabling offline cracking of weak credentials
- Invariant to test: no derivative of a credential is logged
- Expected Immunefi impact: credential disclosure via log-derived hashes (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
