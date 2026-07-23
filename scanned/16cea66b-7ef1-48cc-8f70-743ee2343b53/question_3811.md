# Q3811: newBinaryStorageIterator trie proof acceptance differential

## Question
Can an unprivileged attacker reach `newBinaryStorageIterator` through node-data or proof response from a sync peer using snapshot chunks, trie nodes, proofs, account or storage ranges, packet ordering, and peer mix and make `newBinaryStorageIterator` accept a proof that resolves to a different account or storage slot than intended, causing the invariant that every accepted proof must bind one unique path to one unique value under the advertised root to fail and leading to Stealing or loss of funds?

## Target
- File/function: snapshot/iterator_binary.go:216 (newBinaryStorageIterator)
- Entrypoint: node-data or proof response from a sync peer
- Attacker controls: snapshot chunks, trie nodes, proofs, account or storage ranges, packet ordering, and peer mix
- Exploit idea: make `newBinaryStorageIterator` accept a proof that resolves to a different account or storage slot than intended
- Invariant to test: every accepted proof must bind one unique path to one unique value under the advertised root
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: feed alternate proof encodings for the same path and assert verifier output and imported state cannot diverge
