# Q6664: revertTrienodeHealRequest journal or rebuild resurrection

## Question
Can an unprivileged attacker reach `revertTrienodeHealRequest` through snapshot journal, cap, rebuild, or recovery flow using snapshot chunks, trie nodes, proofs, account or storage ranges, packet ordering, and peer mix and make `revertTrienodeHealRequest` resurrect deleted balances or storage during recovery, causing the invariant that deleted state must remain deleted across snapshot recovery and rebuild operations to fail and leading to Balance manipulation?

## Target
- File/function: node/cn/snap/sync.go:1672 (revertTrienodeHealRequest)
- Entrypoint: snapshot journal, cap, rebuild, or recovery flow
- Attacker controls: snapshot chunks, trie nodes, proofs, account or storage ranges, packet ordering, and peer mix
- Exploit idea: make `revertTrienodeHealRequest` resurrect deleted balances or storage during recovery
- Invariant to test: deleted state must remain deleted across snapshot recovery and rebuild operations
- Expected Immunefi impact: Balance manipulation
- Fast validation: force snapshot rebuild after crafted deletions and assert deleted accounts or storage never reappear
