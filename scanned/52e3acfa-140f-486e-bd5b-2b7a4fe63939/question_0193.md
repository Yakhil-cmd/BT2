# Q193: nft-metadata via Search 193

## Question
Can an unprivileged attacker entering through the external NFT link open action in `Search` (packages/gui/src/components/nfts/gallery/NFTGallerySearch.tsx) control metadata URI list with mixed schemes and redirects with a redirected remote resource and drive the sequence preview -> mutate controlled state -> confirm so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGallerySearch.tsx` / `Search`
- Entrypoint: external NFT link open action
- Attacker controls: metadata URI list with mixed schemes and redirects; with a redirected remote resource
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
