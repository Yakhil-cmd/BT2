# Q1984: use_snapshot_archives_at_startup Repair-induced non-deterministic ledger state

## Question
Can attacker-controlled repair or duplicate evidence processed by `ledger/src/use_snapshot_archives_at_startup.rs::default_value` make blockstore retain or prefer different ledger fragments across honest nodes?

## Target
- File/function: ledger/src/use_snapshot_archives_at_startup.rs::default_value
- Entrypoint: malicious shred or block data from a peer below consensus threshold
- Attacker controls: shred fields, coding/data mix, duplication, ordering, ancestry hints, and signatures
- Exploit idea: Target races between duplicate resolution, repair insertion, and ancestor weighting that may leave different durable fragments on disk.
- Invariant to test: Repair and duplicate resolution must not create durable ledger-state divergence across honest nodes.
- Expected Immunefi impact: High. Unintended chain split (network partition)
- Fast validation: Differentially replay the same duplicate/repair traces and compare surviving blockstore fragments and replay results.
