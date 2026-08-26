# Q5860: repoSync.initRepo — ref with control chars under first sync

## Question
Under the very first sync after container start, when the root is empty and syncCount is 0, an attacker creates ref names containing newlines, quotes, or ANSI escapes and lets them reach FETCH_HEAD and log lines. In the repo bootstrap in initRepo() (`git init -b git-sync`, `remote get-url/add/set-url origin`), can that mean the parsed rev-parse output and the JSON log/error-file records are corrupted or spoofed by embedded control characters, so that the invariant “all git output parsed by git-sync is unambiguous regardless of upstream ref names” no longer holds and the outcome is log/error-file forgery masking a real compromise, and mis-parsed hashes?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Creates ref names containing newlines, quotes, or ANSI escapes and lets them reach FETCH_HEAD and log lines. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the parsed rev-parse output and the JSON log/error-file records are corrupted or spoofed by embedded control characters
- Invariant to test: all git output parsed by git-sync is unambiguous regardless of upstream ref names
- Expected Immunefi impact: log/error-file forgery masking a real compromise, and mis-parsed hashes (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: stand up a local bare repo (file:// or `git daemon`), reproduce the ref/object shape, run git-sync for two periods and diff `readlink <link>` against the ref's real tip
