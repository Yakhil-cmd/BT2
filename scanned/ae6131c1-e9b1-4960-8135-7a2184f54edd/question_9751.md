# Q9751: SendServiceChainInfoRequest cross-standard path confusion

## Question
Can an unprivileged attacker reach `SendServiceChainInfoRequest` through ERC20, ERC721, and KLAY bridge paths sharing logic using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `SendServiceChainInfoRequest` execute an ERC20-style settlement on an ERC721 or KLAY path, or the reverse, causing the invariant that asset-standard-specific invariants must hold even when payload shapes overlap to fail and leading to Stealing or loss of funds?

## Target
- File/function: node/sc/bridgepeer.go:245 (SendServiceChainInfoRequest)
- Entrypoint: ERC20, ERC721, and KLAY bridge paths sharing logic
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `SendServiceChainInfoRequest` execute an ERC20-style settlement on an ERC721 or KLAY path, or the reverse
- Invariant to test: asset-standard-specific invariants must hold even when payload shapes overlap
- Expected Immunefi impact: Stealing or loss of funds
- Fast validation: drive crafted payloads across ERC20, ERC721, and KLAY handlers and assert standard-specific accounting never crosses paths
