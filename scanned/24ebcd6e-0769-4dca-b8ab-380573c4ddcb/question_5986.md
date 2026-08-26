# Q5986: repoSync.SyncRepo — ref with control chars under hash pinned

## Question
Starting from `--ref` pinned to a full commit hash, where git-sync sleeps forever after the first successful sync, can an attacker who creates ref names containing newlines, quotes, or ANSI escapes and lets them reach FETCH_HEAD and log lines drive the hash resolution and change-detection logic in SyncRepo() (`rev-parse FETCH_HEAD^{}`, currentHash vs remoteHash, `reset --soft`) to a state where the parsed rev-parse output and the JSON log/error-file records are corrupted or spoofed by embedded control characters, defeating “all git output parsed by git-sync is unambiguous regardless of upstream ref names” and causing log/error-file forgery masking a real compromise, and mis-parsed hashes?

## Target
- File/function: [main.go](main.go) — `repoSync.SyncRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Creates ref names containing newlines, quotes, or ANSI escapes and lets them reach FETCH_HEAD and log lines. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the parsed rev-parse output and the JSON log/error-file records are corrupted or spoofed by embedded control characters
- Invariant to test: all git output parsed by git-sync is unambiguous regardless of upstream ref names
- Expected Immunefi impact: log/error-file forgery masking a real compromise, and mis-parsed hashes (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
