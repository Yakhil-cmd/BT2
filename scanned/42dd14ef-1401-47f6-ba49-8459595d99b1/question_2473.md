# Q2473: onERC721Received cross-standard path confusion

## Question
Can an unprivileged attacker reach `onERC721Received` through ERC20, ERC721, and KLAY bridge paths sharing logic via an on-chain bridge contract call using tokenId, recipient, counterpart message fields, extraData, and replay timing and make `onERC721Received` execute an ERC20-style settlement on an ERC721 or KLAY path, or the reverse, causing the invariant that asset-standard-specific invariants must hold even when payload shapes overlap to fail and leading to Stealing or loss of funds?

## Target
- File/function: contracts/service_chain/bridge/BridgeTransferERC721.sol:onERC721Received
- Entrypoint: ERC20, ERC721, and KLAY bridge paths sharing logic via an on-chain bridge contract call
- Attacker controls: tokenId, recipient, counterpart message fields, extraData, and replay timing
- Exploit idea: make `onERC721Received` execute an ERC20-style settlement on an ERC721 or KLAY path, or the reverse
- Invariant to test: asset-standard-specific invariants must hold even when payload shapes overlap
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: drive crafted payloads across ERC20, ERC721, and KLAY handlers and assert standard-specific accounting never crosses paths
