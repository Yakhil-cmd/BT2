# Q1167: block_id_repair_service State accumulation without bounded reclamation

## Question
Can repair protocol request or response from a non-privileged network peer drive `core/src/repair/block_id_repair_service.rs::remove_expected_ping_response` with attacker-controlled repair packet contents, ancestry claims, response ordering, and peer timing that accumulate long-lived connection, queue, cache, or retry state faster than it is reclaimed, eventually degrading or shutting down part of the node fleet without brute force?

## Target
- File/function: core/src/repair/block_id_repair_service.rs::remove_expected_ping_response
- Entrypoint: repair protocol request or response from a non-privileged network peer
- Attacker controls: repair packet contents, ancestry claims, response ordering, and peer timing
- Exploit idea: Focus on eviction gaps, retry bookkeeping, stream lifecycle leaks, and peer state that persists after validation failure.
- Invariant to test: Attacker-triggerable state tied to public ingress must remain bounded and must be reclaimable under adversarial churn.
- Expected Immunefi impact: Medium. Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network
- Fast validation: Stress churn-heavy adversarial sessions and assert bounded memory/object counts and successful reclamation after disconnect or rejection.
