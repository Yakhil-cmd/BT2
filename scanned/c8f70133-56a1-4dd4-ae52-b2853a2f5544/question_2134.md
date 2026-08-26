# Q2134: repoSync.SyncRepo — deleted ref wedge under short period

## Question
Can an unprivileged attacker who deletes the branch or tag named by --ref after a successful sync, under a short `--period` (seconds), so syncs overlap the attacker's push cadence, reach a state where — in the hash resolution and change-detection logic in SyncRepo() (`rev-parse FETCH_HEAD^{}`, currentHash vs remoteHash, `reset --soft`) — every subsequent fetch fails, failCount climbs, and the process exits at --max-failures while the last-published symlink stays live and readiness stays true, breaking the invariant that sync failure is surfaced to consumers rather than masked by an already-ready symlink and yielding silent staleness / denial of updates to the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.SyncRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Deletes the branch or tag named by --ref after a successful sync. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: every subsequent fetch fails, failCount climbs, and the process exits at --max-failures while the last-published symlink stays live and readiness stays true
- Invariant to test: sync failure is surfaced to consumers rather than masked by an already-ready symlink
- Expected Immunefi impact: silent staleness / denial of updates to the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: stand up a local bare repo (file:// or `git daemon`), reproduce the ref/object shape, run git-sync for two periods and diff `readlink <link>` against the ref's real tip
