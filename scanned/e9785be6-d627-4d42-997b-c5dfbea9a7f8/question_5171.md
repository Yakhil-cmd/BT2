# Q5171: StakingInfoIdlePeers partial sync commit

## Question
Can an unprivileged attacker reach `StakingInfoIdlePeers` through fast-sync or snap-sync commit path using snapshot chunks, trie nodes, proofs, account or storage ranges, packet ordering, and peer mix and make `StakingInfoIdlePeers` commit partially validated state that later peers can build on, causing the invariant that only fully validated state batches may become durable sync checkpoints to fail and leading to Balance manipulation?

## Target
- File/function: datasync/downloader/peer.go:571 (StakingInfoIdlePeers)
- Entrypoint: fast-sync or snap-sync commit path
- Attacker controls: snapshot chunks, trie nodes, proofs, account or storage ranges, packet ordering, and peer mix
- Exploit idea: make `StakingInfoIdlePeers` commit partially validated state that later peers can build on
- Invariant to test: only fully validated state batches may become durable sync checkpoints
- Expected Immunefi impact: Balance manipulation
- Fast validation: interrupt validation between batch stages and assert restart cannot resurrect unverified state
