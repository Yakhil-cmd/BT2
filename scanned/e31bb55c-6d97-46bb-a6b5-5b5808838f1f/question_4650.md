# Q4650: repoSync.StoreCredentials — password file rotation under github app

## Question
Under GitHub App auth with `--github-app-*` flags, an attacker times a sync against password-file rotation so a partially-written file is read. In StoreCredentials(): the `url=/username=/password=` blob piped into `git credential approve`, can that mean a truncated password is stored and every later fetch fails, tripping --max-failures, so that the invariant “credential reads are atomic with respect to rotation” no longer holds and the outcome is denial of updates / container crash loop?

## Target
- File/function: [main.go](main.go) — `repoSync.StoreCredentials`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Times a sync against password-file rotation so a partially-written file is read. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a truncated password is stored and every later fetch fails, tripping --max-failures
- Invariant to test: credential reads are atomic with respect to rotation
- Expected Immunefi impact: denial of updates / container crash loop (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
