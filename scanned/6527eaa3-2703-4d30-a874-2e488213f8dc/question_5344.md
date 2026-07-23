# Q5344: newTrie partial sync commit

## Question
Can an unprivileged attacker reach `newTrie` through fast-sync or snap-sync commit path using snapshot chunks, trie nodes, proofs, account or storage ranges, packet ordering, and peer mix and make `newTrie` commit partially validated state that later peers can build on, causing the invariant that only fully validated state batches may become durable sync checkpoints to fail and leading to Balance manipulation?

## Target
- File/function: storage/statedb/trie.go:111 (newTrie)
- Entrypoint: fast-sync or snap-sync commit path
- Attacker controls: snapshot chunks, trie nodes, proofs, account or storage ranges, packet ordering, and peer mix
- Exploit idea: make `newTrie` commit partially validated state that later peers can build on
- Invariant to test: only fully validated state batches may become durable sync checkpoints
- Expected Immunefi impact: Balance manipulation
- Fast validation: interrupt validation between batch stages and assert restart cannot resurrect unverified state
