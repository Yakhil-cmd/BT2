# Q1991: nft-metadata via launcherIdFromNFTId 1991

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `launcherIdFromNFTId` (packages/gui/src/util/nfts.ts) control HTML/SVG/media content rendered in preview after a profile switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/nfts.ts` / `launcherIdFromNFTId`
- Entrypoint: on-demand NFT data provider
- Attacker controls: HTML/SVG/media content rendered in preview; after a profile switch
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
