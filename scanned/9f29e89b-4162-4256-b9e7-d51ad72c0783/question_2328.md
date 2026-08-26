# Q2328: repoSync.RefreshGitHubAppToken — ssh command injection under password file

## Question
Does RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage stay safe when an attacker targets the string concatenation in SetupGitSSH() (`-i %s` per key path, UserKnownHostsFile=%s) with any value that can carry spaces or options in `--password-file`, re-read on every sync for rotation — or can extra ssh options are smuggled into `$GIT_SSH_COMMAND` and take effect for every later fetch, including submodule fetches, violating “the ssh command line is built from properly separated arguments” and producing ssh option injection: key exposure or host verification bypass?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Targets the string concatenation in SetupGitSSH() (`-i %s` per key path, UserKnownHostsFile=%s) with any value that can carry spaces or options. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: extra ssh options are smuggled into `$GIT_SSH_COMMAND` and take effect for every later fetch, including submodule fetches
- Invariant to test: the ssh command line is built from properly separated arguments
- Expected Immunefi impact: ssh option injection: key exposure or host verification bypass (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
