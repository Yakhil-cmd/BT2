# Q9697: handleERC721Transfer journal or recovery duplication

## Question
Can an unprivileged attacker reach `handleERC721Transfer` through bridge journal, recovery, or replay handling via an on-chain bridge contract call using tokenId, recipient, counterpart message fields, extraData, and replay timing and make `handleERC721Transfer` reprocess an already-settled bridge event after recovery, causing the invariant that bridge recovery must be idempotent for every settled request nonce to fail and leading to Stealing or loss of funds?

## Target
- File/function: contracts/service_chain/bridge/BridgeTransferERC721.sol:handleERC721Transfer
- Entrypoint: bridge journal, recovery, or replay handling via an on-chain bridge contract call
- Attacker controls: tokenId, recipient, counterpart message fields, extraData, and replay timing
- Exploit idea: make `handleERC721Transfer` reprocess an already-settled bridge event after recovery
- Invariant to test: bridge recovery must be idempotent for every settled request nonce
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: restart bridge components after partial settlement and assert recovered journals cannot settle the same request twice
