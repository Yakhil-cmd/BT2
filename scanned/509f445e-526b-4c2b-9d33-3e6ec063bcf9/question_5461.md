# Q5461: parseQString — fsmonitor hook under gc always

## Question
Under `--git-gc=always`, so maintenance config matters every period, an attacker gets `core.fsmonitor` set to a path inside the checked-out tree. In the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val(), can that mean git executes the attacker's file on the next repository operation, so that the invariant “no config points at executables inside the working tree” no longer holds and the outcome is remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Gets `core.fsmonitor` set to a path inside the checked-out tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git executes the attacker's file on the next repository operation
- Invariant to test: no config points at executables inside the working tree
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
