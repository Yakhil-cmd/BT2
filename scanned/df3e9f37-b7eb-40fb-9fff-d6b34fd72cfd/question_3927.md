# Q3927: nft-metadata via NFTGalleryScrollPositionProvider 3927

## Question
Can an unprivileged attacker entering through the external NFT link open action in `NFTGalleryScrollPositionProvider` (packages/gui/src/components/nfts/gallery/NFTGalleryScrollPositionProvider.tsx) control metadata URI list with mixed schemes and redirects after a profile switch and drive the sequence select -> edit backing object -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGalleryScrollPositionProvider.tsx` / `NFTGalleryScrollPositionProvider`
- Entrypoint: external NFT link open action
- Attacker controls: metadata URI list with mixed schemes and redirects; after a profile switch
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
