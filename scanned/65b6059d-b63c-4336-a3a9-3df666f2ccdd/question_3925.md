# Q3925: nft-metadata via NFTGalleryHero 3925

## Question
Can an unprivileged attacker entering through the external NFT link open action in `NFTGalleryHero` (packages/gui/src/components/nfts/gallery/NFTGalleryHero.tsx) control HTML/SVG/media content rendered in preview with a cached permission entry and drive the sequence open notification -> resolve details -> execute so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGalleryHero.tsx` / `NFTGalleryHero`
- Entrypoint: external NFT link open action
- Attacker controls: HTML/SVG/media content rendered in preview; with a cached permission entry
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
