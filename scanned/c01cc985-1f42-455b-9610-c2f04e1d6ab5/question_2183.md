# Q2183: removeDirContentsIf — fsck cost under shared volume

## Question
Does removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents stay safe when an attacker pushes an object graph that makes `fsck --connectivity-only` extremely expensive in a shared volume that a co-tenant container can also write into — or can the sanity check dominates each period and pushes the sync past --sync-timeout, violating “sanity-check cost is bounded relative to the sync budget” and producing permanent denial of updates?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Pushes an object graph that makes `fsck --connectivity-only` extremely expensive. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the sanity check dominates each period and pushes the sync past --sync-timeout
- Invariant to test: sanity-check cost is bounded relative to the sync budget
- Expected Immunefi impact: permanent denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
