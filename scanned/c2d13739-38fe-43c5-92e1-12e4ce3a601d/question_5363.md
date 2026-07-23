# Q5363: onERC721Received asset mapping drift

## Question
Can an unprivileged attacker reach `onERC721Received` through bridge request or handle flow for ERC20, ERC721, or KLAY assets via an on-chain bridge contract call using tokenId, recipient, counterpart message fields, extraData, and replay timing and make `onERC721Received` release or mint a different asset than the asset originally locked, causing the invariant that the asset unlocked on one side must exactly match the asset locked on the other side to fail and leading to Stealing or loss of funds?

## Target
- File/function: contracts/service_chain/bridge/BridgeTransferERC721.sol:onERC721Received
- Entrypoint: bridge request or handle flow for ERC20, ERC721, or KLAY assets via an on-chain bridge contract call
- Attacker controls: tokenId, recipient, counterpart message fields, extraData, and replay timing
- Exploit idea: make `onERC721Received` release or mint a different asset than the asset originally locked
- Invariant to test: the asset unlocked on one side must exactly match the asset locked on the other side
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: bridge a crafted asset mapping and assert the destination asset, amount, and recipient remain one-to-one with the source lock
