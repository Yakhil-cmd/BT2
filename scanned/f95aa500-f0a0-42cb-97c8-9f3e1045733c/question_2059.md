# Q2059: nft-metadata via NFTGalleryScrollPositionProvider 2059

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `NFTGalleryScrollPositionProvider` (packages/gui/src/components/nfts/gallery/NFTGalleryScrollPositionProvider.tsx) control filename and MIME/type mismatch during download with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGalleryScrollPositionProvider.tsx` / `NFTGalleryScrollPositionProvider`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: filename and MIME/type mismatch during download; with hidden Unicode characters
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
