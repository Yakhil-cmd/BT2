# Q1101: nft-metadata via NFTPreviewDialog 1101

## Question
Can an unprivileged attacker entering through the external NFT link open action in `NFTPreviewDialog` (packages/gui/src/components/nfts/NFTPreviewDialog.tsx) control HTML/SVG/media content rendered in preview with case-normalized identifiers and drive the sequence preview -> mutate controlled state -> confirm so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTPreviewDialog.tsx` / `NFTPreviewDialog`
- Entrypoint: external NFT link open action
- Attacker controls: HTML/SVG/media content rendered in preview; with case-normalized identifiers
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
