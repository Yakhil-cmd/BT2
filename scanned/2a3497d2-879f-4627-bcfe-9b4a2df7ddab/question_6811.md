# Q6811: unlockKLAY recipient or callback confusion

## Question
Can an unprivileged attacker reach `unlockKLAY` through bridge callback or receiver hook via an on-chain bridge contract call using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `unlockKLAY` finalize transfer value to a recipient different from the intended beneficiary, causing the invariant that callback-driven settlement must not be able to rewrite the intended recipient or fee payer to fail and leading to Stealing or loss of funds?

## Target
- File/function: contracts/service_chain/bridge/BridgeTransferKLAY.sol:unlockKLAY
- Entrypoint: bridge callback or receiver hook via an on-chain bridge contract call
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `unlockKLAY` finalize transfer value to a recipient different from the intended beneficiary
- Invariant to test: callback-driven settlement must not be able to rewrite the intended recipient or fee payer
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: bridge to a malicious receiver contract and assert callback-controlled fields cannot redirect the payout
