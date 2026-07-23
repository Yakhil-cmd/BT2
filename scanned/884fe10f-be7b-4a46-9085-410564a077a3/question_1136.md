# Q1136: checkRecoveryCandidateCondition journal or recovery duplication

## Question
Can an unprivileged attacker reach `checkRecoveryCandidateCondition` through bridge journal, recovery, or replay handling using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `checkRecoveryCandidateCondition` reprocess an already-settled bridge event after recovery, causing the invariant that bridge recovery must be idempotent for every settled request nonce to fail and leading to Stealing or loss of funds?

## Target
- File/function: node/sc/vt_recovery.go:363 (checkRecoveryCandidateCondition)
- Entrypoint: bridge journal, recovery, or replay handling
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `checkRecoveryCandidateCondition` reprocess an already-settled bridge event after recovery
- Invariant to test: bridge recovery must be idempotent for every settled request nonce
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: restart bridge components after partial settlement and assert recovered journals cannot settle the same request twice
