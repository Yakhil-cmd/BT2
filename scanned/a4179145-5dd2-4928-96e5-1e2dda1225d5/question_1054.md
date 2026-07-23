# Q1054: UnLock request replay

## Question
Can an unprivileged attacker reach `UnLock` through public bridge deposit or withdrawal request flow using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `UnLock` accept the same bridge intent twice across request and handle paths, causing the invariant that one deposit or bridge request must authorize at most one release, mint, or unlock to fail and leading to Stealing or loss of funds?

## Target
- File/function: node/sc/bridge_accounts.go:310 (UnLock)
- Entrypoint: public bridge deposit or withdrawal request flow
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `UnLock` accept the same bridge intent twice across request and handle paths
- Invariant to test: one deposit or bridge request must authorize at most one release, mint, or unlock
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: replay the same bridge request or event context twice on a local fork and assert only one outbound release can succeed
