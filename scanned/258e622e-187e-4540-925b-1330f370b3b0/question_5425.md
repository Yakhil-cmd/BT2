# Q5425: parseQString — fsmonitor hook under http auth

## Question
Can an unprivileged attacker who gets `core.fsmonitor` set to a path inside the checked-out tree, under HTTPS auth, where credential caching is live, reach a state where — in the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val() — git executes the attacker's file on the next repository operation, breaking the invariant that no config points at executables inside the working tree and yielding remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets `core.fsmonitor` set to a path inside the checked-out tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git executes the attacker's file on the next repository operation
- Invariant to test: no config points at executables inside the working tree
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: dump `git config list -z` under GIT_CONFIG_GLOBAL after the fixture sync and assert the effective keys equal the intended set
