# Q1089: HandleSubMsg asset mapping drift

## Question
Can an unprivileged attacker reach `HandleSubMsg` through bridge request or handle flow for ERC20, ERC721, or KLAY assets using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `HandleSubMsg` release or mint a different asset than the asset originally locked, causing the invariant that the asset unlocked on one side must exactly match the asset locked on the other side to fail and leading to Stealing or loss of funds?

## Target
- File/function: node/sc/main_bridge_handler.go:48 (HandleSubMsg)
- Entrypoint: bridge request or handle flow for ERC20, ERC721, or KLAY assets
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `HandleSubMsg` release or mint a different asset than the asset originally locked
- Invariant to test: the asset unlocked on one side must exactly match the asset locked on the other side
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: bridge a crafted asset mapping and assert the destination asset, amount, and recipient remain one-to-one with the source lock
