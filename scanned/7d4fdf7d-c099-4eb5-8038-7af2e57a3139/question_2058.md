# Q2058: nft-metadata via NFTGalleryScrollPositionProvider 2058

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `NFTGalleryScrollPositionProvider` (packages/gui/src/components/nfts/gallery/NFTGalleryScrollPositionProvider.tsx) control HTML/SVG/media content rendered in preview with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGalleryScrollPositionProvider.tsx` / `NFTGalleryScrollPositionProvider`
- Entrypoint: on-demand NFT data provider
- Attacker controls: HTML/SVG/media content rendered in preview; with hidden Unicode characters
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
