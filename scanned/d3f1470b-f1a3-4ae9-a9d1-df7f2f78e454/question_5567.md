# Q5567: removeDirContentsIf — disk full partial write under gc always

## Question
Can an unprivileged attacker who fills the volume with committed content so a later publish or cleanup hits ENOSPC, under `--git-gc=always`, reach a state where — in removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents — the half-written state is neither published cleanly nor rolled back, and readiness still reports success, breaking the invariant that ENOSPC leaves a consistent, correctly-reported state and yielding silent serving of corrupt/partial content?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Fills the volume with committed content so a later publish or cleanup hits ENOSPC. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the half-written state is neither published cleanly nor rolled back, and readiness still reports success
- Invariant to test: ENOSPC leaves a consistent, correctly-reported state
- Expected Immunefi impact: silent serving of corrupt/partial content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
