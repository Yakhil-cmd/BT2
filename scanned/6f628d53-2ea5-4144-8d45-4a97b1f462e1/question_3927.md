# Q3927: doSubscribeBridge asset mapping drift

## Question
Can an unprivileged attacker reach `doSubscribeBridge` through bridge request or handle flow for ERC20, ERC721, or KLAY assets using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `doSubscribeBridge` release or mint a different asset than the asset originally locked, causing the invariant that the asset unlocked on one side must exactly match the asset locked on the other side to fail and leading to Stealing or loss of funds?

## Target
- File/function: node/sc/api_bridge.go:175 (doSubscribeBridge)
- Entrypoint: bridge request or handle flow for ERC20, ERC721, or KLAY assets
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `doSubscribeBridge` release or mint a different asset than the asset originally locked
- Invariant to test: the asset unlocked on one side must exactly match the asset locked on the other side
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: bridge a crafted asset mapping and assert the destination asset, amount, and recipient remain one-to-one with the source lock
