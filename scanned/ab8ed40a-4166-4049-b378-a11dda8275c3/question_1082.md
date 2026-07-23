# Q1082: SendServiceChainReceiptRequest request replay

## Question
Can an unprivileged attacker reach `SendServiceChainReceiptRequest` through public bridge deposit or withdrawal request flow using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `SendServiceChainReceiptRequest` accept the same bridge intent twice across request and handle paths, causing the invariant that one deposit or bridge request must authorize at most one release, mint, or unlock to fail and leading to Stealing or loss of funds?

## Target
- File/function: node/sc/bridgepeer.go:253 (SendServiceChainReceiptRequest)
- Entrypoint: public bridge deposit or withdrawal request flow
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `SendServiceChainReceiptRequest` accept the same bridge intent twice across request and handle paths
- Invariant to test: one deposit or bridge request must authorize at most one release, mint, or unlock
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: replay the same bridge request or event context twice on a local fork and assert only one outbound release can succeed
