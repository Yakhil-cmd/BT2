# Q2384: Exechook.Do — hook hash skipping under both hooks

## Question
Does Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() stay safe when an attacker publishes several hashes faster than the hook completes in a deployment using both exec and web hooks — or can the single-slot channel and lastHash logic silently skip intermediate hashes, so a hook meant to validate every revision never sees some, violating “every published revision is observed by the hook, or skipping is surfaced” and producing bypass of a security-relevant post-sync validation step?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Publishes several hashes faster than the hook completes. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the single-slot channel and lastHash logic silently skip intermediate hashes, so a hook meant to validate every revision never sees some
- Invariant to test: every published revision is observed by the hook, or skipping is surfaced
- Expected Immunefi impact: bypass of a security-relevant post-sync validation step (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
