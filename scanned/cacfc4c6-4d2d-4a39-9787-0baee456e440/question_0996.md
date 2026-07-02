# Q996: tower_storage Vote-order manipulation against lockout invariants

## Question
Can a below-threshold adversary shape fork timing, vote ordering, duplicate shreds, ancestry hints, and replay-visible state entering `core/src/consensus/tower_storage.rs::from` from vote, shred, or transaction input that influences replay so vote ordering or lockout bookkeeping violates Tower-style safety assumptions on some nodes but not others?

## Target
- File/function: core/src/consensus/tower_storage.rs::from
- Entrypoint: vote, shred, or transaction input that influences replay
- Attacker controls: fork timing, vote ordering, duplicate shreds, ancestry hints, and replay-visible state
- Exploit idea: Probe races between vote ingestion, duplicate handling, rollback, and rooted-bank updates that may misapply or forget lockouts.
- Invariant to test: Lockout and vote-state transitions must remain deterministic and monotonic under adversarial but reachable vote timing.
- Expected Immunefi impact: High. Unintended chain split (network partition)
- Fast validation: Fuzz vote arrival and rollback interleavings and assert monotonic lockout/accounting invariants across replicas.
