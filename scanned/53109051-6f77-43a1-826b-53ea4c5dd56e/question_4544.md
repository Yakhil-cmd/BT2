# Q4544: Exechook.Do — cmdforlog spoof under exechook

## Question
Does Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() stay safe when an attacker gets attacker bytes (paths, hashes, ref names) into argv that reaches cmdForLog() in a deployment using `--exechook-command` — or can quoting only triggers on space/tab/newline, so quotes and control characters forge convincing fake command lines in the JSON log and error file, violating “logged command lines are unambiguous for all argv” and producing audit-log forgery concealing an in-progress compromise?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Gets attacker bytes (paths, hashes, ref names) into argv that reaches cmdForLog(). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: quoting only triggers on space/tab/newline, so quotes and control characters forge convincing fake command lines in the JSON log and error file
- Invariant to test: logged command lines are unambiguous for all argv
- Expected Immunefi impact: audit-log forgery concealing an in-progress compromise (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
