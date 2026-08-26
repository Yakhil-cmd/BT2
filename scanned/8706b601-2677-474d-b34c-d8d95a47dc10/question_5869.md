# Q5869: repoSync.fetch — ref with control chars under depth1

## Question
Starting from a deployment using `--depth=1` (the documented shallow default for large repos), can an attacker who creates ref names containing newlines, quotes, or ANSI escapes and lets them reach FETCH_HEAD and log lines drive the argv assembled in fetch() (`fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc` plus --depth/--unshallow/--filter) to a state where the parsed rev-parse output and the JSON log/error-file records are corrupted or spoofed by embedded control characters, defeating “all git output parsed by git-sync is unambiguous regardless of upstream ref names” and causing log/error-file forgery masking a real compromise, and mis-parsed hashes?

## Target
- File/function: [main.go](main.go) — `repoSync.fetch`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Creates ref names containing newlines, quotes, or ANSI escapes and lets them reach FETCH_HEAD and log lines. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the parsed rev-parse output and the JSON log/error-file records are corrupted or spoofed by embedded control characters
- Invariant to test: all git output parsed by git-sync is unambiguous regardless of upstream ref names
- Expected Immunefi impact: log/error-file forgery masking a real compromise, and mis-parsed hashes (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
