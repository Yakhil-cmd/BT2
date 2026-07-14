# Q191: nft-metadata via NFTGalleryScrollPositionProvider 191

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `NFTGalleryScrollPositionProvider` (packages/gui/src/components/nfts/gallery/NFTGalleryScrollPositionProvider.tsx) control metadata URI list with mixed schemes and redirects with a redirected remote resource and drive the sequence validate input -> normalize payload -> call RPC so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGalleryScrollPositionProvider.tsx` / `NFTGalleryScrollPositionProvider`
- Entrypoint: multiple NFT download action
- Attacker controls: metadata URI list with mixed schemes and redirects; with a redirected remote resource
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
