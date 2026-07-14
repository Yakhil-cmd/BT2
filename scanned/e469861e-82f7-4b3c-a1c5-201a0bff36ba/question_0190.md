# Q190: nft-metadata via NFTGalleryScrollPositionProvider 190

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `NFTGalleryScrollPositionProvider` (packages/gui/src/components/nfts/gallery/NFTGalleryScrollPositionProvider.tsx) control metadata URI list with mixed schemes and redirects with a redirected remote resource and drive the sequence validate input -> normalize payload -> call RPC so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGalleryScrollPositionProvider.tsx` / `NFTGalleryScrollPositionProvider`
- Entrypoint: NFT preview dialog
- Attacker controls: metadata URI list with mixed schemes and redirects; with a redirected remote resource
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
