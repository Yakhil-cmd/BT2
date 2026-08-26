# Q2564: Exechook.Do — hook hash skipping under error file

## Question
Starting from `--error-file` enabled inside --root, can an attacker who publishes several hashes faster than the hook completes drive Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() to a state where the single-slot channel and lastHash logic silently skip intermediate hashes, so a hook meant to validate every revision never sees some, defeating “every published revision is observed by the hook, or skipping is surfaced” and causing bypass of a security-relevant post-sync validation step?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Publishes several hashes faster than the hook completes. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the single-slot channel and lastHash logic silently skip intermediate hashes, so a hook meant to validate every revision never sees some
- Invariant to test: every published revision is observed by the hook, or skipping is surfaced
- Expected Immunefi impact: bypass of a security-relevant post-sync validation step (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
