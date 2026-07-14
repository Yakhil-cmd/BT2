# Q2023: nft-metadata via isHidden 2023

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `isHidden` (packages/gui/src/components/nfts/NFTCard.tsx) control HTML/SVG/media content rendered in preview during a pending modal confirmation and drive the sequence fetch -> cache -> refresh -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTCard.tsx` / `isHidden`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; during a pending modal confirmation
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
