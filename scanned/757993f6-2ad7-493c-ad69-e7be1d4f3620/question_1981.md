# Q1981: repoSync.fetch — deleted ref wedge under depth1

## Question
Starting from a deployment using `--depth=1` (the documented shallow default for large repos), can an attacker who deletes the branch or tag named by --ref after a successful sync drive the argv assembled in fetch() (`fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc` plus --depth/--unshallow/--filter) to a state where every subsequent fetch fails, failCount climbs, and the process exits at --max-failures while the last-published symlink stays live and readiness stays true, defeating “sync failure is surfaced to consumers rather than masked by an already-ready symlink” and causing silent staleness / denial of updates to the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.fetch`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Deletes the branch or tag named by --ref after a successful sync. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: every subsequent fetch fails, failCount climbs, and the process exits at --max-failures while the last-published symlink stays live and readiness stays true
- Invariant to test: sync failure is surfaced to consumers rather than masked by an already-ready symlink
- Expected Immunefi impact: silent staleness / denial of updates to the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
