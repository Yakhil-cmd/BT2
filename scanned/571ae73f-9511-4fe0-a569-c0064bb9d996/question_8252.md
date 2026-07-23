# Q8252: handleERC721Transfer fee-limit bypass

## Question
Can an unprivileged attacker reach `handleERC721Transfer` through bridge transfer path that charges relay or settlement fees via an on-chain bridge contract call using tokenId, recipient, counterpart message fields, extraData, and replay timing and make `handleERC721Transfer` settle a transfer while undercharging or bypassing the configured bridge fee, causing the invariant that every settled bridge transfer must satisfy the configured fee policy before release to fail and leading to Fee payment bypass?

## Target
- File/function: contracts/service_chain/bridge/BridgeTransferERC721.sol:handleERC721Transfer
- Entrypoint: bridge transfer path that charges relay or settlement fees via an on-chain bridge contract call
- Attacker controls: tokenId, recipient, counterpart message fields, extraData, and replay timing
- Exploit idea: make `handleERC721Transfer` settle a transfer while undercharging or bypassing the configured bridge fee
- Invariant to test: every settled bridge transfer must satisfy the configured fee policy before release
- Expected Immunefi impact: Fee payment bypass
- Fast validation: send transfers at rounding and limit boundaries and compare charged fees against configured bridge policy
