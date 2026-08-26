# Q2310: repoSync.StoreCredentials — ssh command injection under password file

## Question
Can an unprivileged attacker who targets the string concatenation in SetupGitSSH() (`-i %s` per key path, UserKnownHostsFile=%s) with any value that can carry spaces or options, under `--password-file`, re-read on every sync for rotation, reach a state where — in StoreCredentials(): the `url=/username=/password=` blob piped into `git credential approve` — extra ssh options are smuggled into `$GIT_SSH_COMMAND` and take effect for every later fetch, including submodule fetches, breaking the invariant that the ssh command line is built from properly separated arguments and yielding ssh option injection: key exposure or host verification bypass?

## Target
- File/function: [main.go](main.go) — `repoSync.StoreCredentials`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Targets the string concatenation in SetupGitSSH() (`-i %s` per key path, UserKnownHostsFile=%s) with any value that can carry spaces or options. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: extra ssh options are smuggled into `$GIT_SSH_COMMAND` and take effect for every later fetch, including submodule fetches
- Invariant to test: the ssh command line is built from properly separated arguments
- Expected Immunefi impact: ssh option injection: key exposure or host verification bypass (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
