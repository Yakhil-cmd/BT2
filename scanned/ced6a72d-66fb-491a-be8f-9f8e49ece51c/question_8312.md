# Q8312: Nonce journal or recovery duplication

## Question
Can an unprivileged attacker reach `Nonce` through bridge journal, recovery, or replay handling using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `Nonce` reprocess an already-settled bridge event after recovery, causing the invariant that bridge recovery must be idempotent for every settled request nonce to fail and leading to Stealing or loss of funds?

## Target
- File/function: node/sc/event_interface.go:46 (Nonce)
- Entrypoint: bridge journal, recovery, or replay handling
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `Nonce` reprocess an already-settled bridge event after recovery
- Invariant to test: bridge recovery must be idempotent for every settled request nonce
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: restart bridge components after partial settlement and assert recovered journals cannot settle the same request twice
