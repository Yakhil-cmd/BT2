# Q2537: nft-metadata via process 2537

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `process` (packages/gui/src/hooks/useNFTs.ts) control HTML/SVG/media content rendered in preview with precision-boundary values and drive the sequence connect -> approve -> switch context -> execute so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTs.ts` / `process`
- Entrypoint: on-demand NFT data provider
- Attacker controls: HTML/SVG/media content rendered in preview; with precision-boundary values
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
