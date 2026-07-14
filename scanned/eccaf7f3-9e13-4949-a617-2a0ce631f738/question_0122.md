# Q122: nft-metadata via isValidNFTId 122

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `isValidNFTId` (packages/gui/src/util/nfts.ts) control HTML/SVG/media content rendered in preview with hidden Unicode characters and drive the sequence import -> parse -> preview -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/nfts.ts` / `isValidNFTId`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: HTML/SVG/media content rendered in preview; with hidden Unicode characters
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
