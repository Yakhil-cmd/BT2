# Q3989: writeChildChainTxHashFromBlock recipient or callback confusion

## Question
Can an unprivileged attacker reach `writeChildChainTxHashFromBlock` through bridge callback or receiver hook using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `writeChildChainTxHashFromBlock` finalize transfer value to a recipient different from the intended beneficiary, causing the invariant that callback-driven settlement must not be able to rewrite the intended recipient or fee payer to fail and leading to Stealing or loss of funds?

## Target
- File/function: node/sc/main_event_handler.go:104 (writeChildChainTxHashFromBlock)
- Entrypoint: bridge callback or receiver hook
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `writeChildChainTxHashFromBlock` finalize transfer value to a recipient different from the intended beneficiary
- Invariant to test: callback-driven settlement must not be able to rewrite the intended recipient or fee payer
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: bridge to a malicious receiver contract and assert callback-controlled fields cannot redirect the payout
