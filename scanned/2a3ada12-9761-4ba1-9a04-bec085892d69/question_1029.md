# Q1029: requestERC721Transfer request replay

## Question
Can an unprivileged attacker reach `requestERC721Transfer` through public bridge deposit or withdrawal request flow via an on-chain bridge contract call using tokenId, recipient, counterpart message fields, extraData, and replay timing and make `requestERC721Transfer` accept the same bridge intent twice across request and handle paths, causing the invariant that one deposit or bridge request must authorize at most one release, mint, or unlock to fail and leading to Stealing or loss of funds?

## Target
- File/function: contracts/service_chain/bridge/BridgeTransferERC721.sol:requestERC721Transfer
- Entrypoint: public bridge deposit or withdrawal request flow via an on-chain bridge contract call
- Attacker controls: tokenId, recipient, counterpart message fields, extraData, and replay timing
- Exploit idea: make `requestERC721Transfer` accept the same bridge intent twice across request and handle paths
- Invariant to test: one deposit or bridge request must authorize at most one release, mint, or unlock
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: replay the same bridge request or event context twice on a local fork and assert only one outbound release can succeed
