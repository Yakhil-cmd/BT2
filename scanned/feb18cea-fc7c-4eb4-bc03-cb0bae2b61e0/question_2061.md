# Q2061: nft-metadata via Search 2061

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `Search` (packages/gui/src/components/nfts/gallery/NFTGallerySearch.tsx) control HTML/SVG/media content rendered in preview with hidden Unicode characters and drive the sequence select -> edit backing object -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGallerySearch.tsx` / `Search`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; with hidden Unicode characters
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
