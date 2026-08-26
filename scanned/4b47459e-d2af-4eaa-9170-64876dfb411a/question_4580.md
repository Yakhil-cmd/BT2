# Q4580: Exechook.Do — cmdforlog spoof under prepub hook

## Question
Starting from a deployment using `--pre-publish-exechook-command`, can an attacker who gets attacker bytes (paths, hashes, ref names) into argv that reaches cmdForLog() drive Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() to a state where quoting only triggers on space/tab/newline, so quotes and control characters forge convincing fake command lines in the JSON log and error file, defeating “logged command lines are unambiguous for all argv” and causing audit-log forgery concealing an in-progress compromise?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Gets attacker bytes (paths, hashes, ref names) into argv that reaches cmdForLog(). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: quoting only triggers on space/tab/newline, so quotes and control characters forge convincing fake command lines in the JSON log and error file
- Invariant to test: logged command lines are unambiguous for all argv
- Expected Immunefi impact: audit-log forgery concealing an in-progress compromise (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
