# Q4715: runWithStdin — cmdforlog spoof under onetime

## Question
Under `--one-time` mode, where hook results gate the exit status, an attacker gets attacker bytes (paths, hashes, ref names) into argv that reaches cmdForLog(). In runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs, can that mean quoting only triggers on space/tab/newline, so quotes and control characters forge convincing fake command lines in the JSON log and error file, so that the invariant “logged command lines are unambiguous for all argv” no longer holds and the outcome is audit-log forgery concealing an in-progress compromise?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Gets attacker bytes (paths, hashes, ref names) into argv that reaches cmdForLog(). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: quoting only triggers on space/tab/newline, so quotes and control characters forge convincing fake command lines in the JSON log and error file
- Invariant to test: logged command lines are unambiguous for all argv
- Expected Immunefi impact: audit-log forgery concealing an in-progress compromise (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
