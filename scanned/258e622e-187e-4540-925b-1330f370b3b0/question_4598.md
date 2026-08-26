# Q4598: Webhook.Do — cmdforlog spoof under prepub hook

## Question
Under a deployment using `--pre-publish-exechook-command`, an attacker gets attacker bytes (paths, hashes, ref names) into argv that reaches cmdForLog(). In Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read, can that mean quoting only triggers on space/tab/newline, so quotes and control characters forge convincing fake command lines in the JSON log and error file, so that the invariant “logged command lines are unambiguous for all argv” no longer holds and the outcome is audit-log forgery concealing an in-progress compromise?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Gets attacker bytes (paths, hashes, ref names) into argv that reaches cmdForLog(). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: quoting only triggers on space/tab/newline, so quotes and control characters forge convincing fake command lines in the JSON log and error file
- Invariant to test: logged command lines are unambiguous for all argv
- Expected Immunefi impact: audit-log forgery concealing an in-progress compromise (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
