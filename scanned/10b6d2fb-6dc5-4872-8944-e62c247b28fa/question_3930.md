# Q3930: nft-metadata via subscribeToChanges 3930

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `subscribeToChanges` (packages/gui/src/components/nfts/provider/NFTProvider.tsx) control HTML/SVG/media content rendered in preview with a redirected remote resource and drive the sequence preview -> mutate controlled state -> confirm so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/NFTProvider.tsx` / `subscribeToChanges`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; with a redirected remote resource
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
