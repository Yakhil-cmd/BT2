# Q4560: repoSync.RefreshGitHubAppToken — password file rotation under http basic

## Question
Can an unprivileged attacker who times a sync against password-file rotation so a partially-written file is read, under HTTPS auth with `--username` and `$GITSYNC_PASSWORD`, reach a state where — in RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage — a truncated password is stored and every later fetch fails, tripping --max-failures, breaking the invariant that credential reads are atomic with respect to rotation and yielding denial of updates / container crash loop?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Times a sync against password-file rotation so a partially-written file is read. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a truncated password is stored and every later fetch fails, tripping --max-failures
- Invariant to test: credential reads are atomic with respect to rotation
- Expected Immunefi impact: denial of updates / container crash loop (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
