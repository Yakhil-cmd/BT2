# Q8254: requestERC721Transfer counterpart authorization gap

## Question
Can an unprivileged attacker reach `requestERC721Transfer` through mainbridge or subbridge message execution or counterpart bridge callback via an on-chain bridge contract call using tokenId, recipient, counterpart message fields, extraData, and replay timing and make `requestERC721Transfer` execute a message from a non-canonical counterpart bridge, causing the invariant that only the configured counterpart bridge may authorize outbound asset release to fail and leading to Unauthorized transaction?

## Target
- File/function: contracts/service_chain/bridge/BridgeTransferERC721.sol:requestERC721Transfer
- Entrypoint: mainbridge or subbridge message execution or counterpart bridge callback via an on-chain bridge contract call
- Attacker controls: tokenId, recipient, counterpart message fields, extraData, and replay timing
- Exploit idea: make `requestERC721Transfer` execute a message from a non-canonical counterpart bridge
- Invariant to test: only the configured counterpart bridge may authorize outbound asset release
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: forge counterpart messages from a non-authorized sender on a local setup and assert release paths always reject them
