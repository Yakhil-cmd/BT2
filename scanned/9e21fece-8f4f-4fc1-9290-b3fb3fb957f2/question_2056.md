# Q2056: nft-metadata via NFTGalleryHero 2056

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `NFTGalleryHero` (packages/gui/src/components/nfts/gallery/NFTGalleryHero.tsx) control objectionable-content flags and hidden NFT state with a delayed metadata fetch and drive the sequence connect -> approve -> switch context -> execute so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGalleryHero.tsx` / `NFTGalleryHero`
- Entrypoint: on-demand NFT data provider
- Attacker controls: objectionable-content flags and hidden NFT state; with a delayed metadata fetch
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
