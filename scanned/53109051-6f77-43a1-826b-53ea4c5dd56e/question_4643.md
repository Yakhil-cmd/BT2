# Q4643: runWithStdin — cmdforlog spoof under webhook

## Question
Starting from a deployment using `--webhook-url`, can an attacker who gets attacker bytes (paths, hashes, ref names) into argv that reaches cmdForLog() drive runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs to a state where quoting only triggers on space/tab/newline, so quotes and control characters forge convincing fake command lines in the JSON log and error file, defeating “logged command lines are unambiguous for all argv” and causing audit-log forgery concealing an in-progress compromise?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Gets attacker bytes (paths, hashes, ref names) into argv that reaches cmdForLog(). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: quoting only triggers on space/tab/newline, so quotes and control characters forge convincing fake command lines in the JSON log and error file
- Invariant to test: logged command lines are unambiguous for all argv
- Expected Immunefi impact: audit-log forgery concealing an in-progress compromise (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
