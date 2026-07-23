# Q2574: restoreBridgeLoop request replay

## Question
Can an unprivileged attacker reach `restoreBridgeLoop` through public bridge deposit or withdrawal request flow using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `restoreBridgeLoop` accept the same bridge intent twice across request and handle paths, causing the invariant that one deposit or bridge request must authorize at most one release, mint, or unlock to fail and leading to Stealing or loss of funds?

## Target
- File/function: node/sc/subbridge.go:587 (restoreBridgeLoop)
- Entrypoint: public bridge deposit or withdrawal request flow
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `restoreBridgeLoop` accept the same bridge intent twice across request and handle paths
- Invariant to test: one deposit or bridge request must authorize at most one release, mint, or unlock
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: replay the same bridge request or event context twice on a local fork and assert only one outbound release can succeed
