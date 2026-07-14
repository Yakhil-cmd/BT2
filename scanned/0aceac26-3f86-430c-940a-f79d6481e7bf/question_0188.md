# Q188: nft-metadata via NFTGalleryHero 188

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `NFTGalleryHero` (packages/gui/src/components/nfts/gallery/NFTGalleryHero.tsx) control content hash/status fields that change across fetches through a batch of rapid user-accessible actions and drive the sequence load persisted state -> render approval -> execute command so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGalleryHero.tsx` / `NFTGalleryHero`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; through a batch of rapid user-accessible actions
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
