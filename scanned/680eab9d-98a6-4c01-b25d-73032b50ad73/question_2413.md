# Q2413: nft-metadata via NFTAttribute 2413

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `NFTAttribute` (packages/api/src/@types/NFTAttribute.ts) control content hash/status fields that change across fetches after a network switch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/@types/NFTAttribute.ts` / `NFTAttribute`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; after a network switch
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
