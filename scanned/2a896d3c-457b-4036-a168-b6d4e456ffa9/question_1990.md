# Q1990: nft-metadata via launcherIdFromNFTId 1990

## Question
Can an unprivileged attacker entering through the external NFT link open action in `launcherIdFromNFTId` (packages/gui/src/util/nfts.ts) control HTML/SVG/media content rendered in preview after a profile switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/nfts.ts` / `launcherIdFromNFTId`
- Entrypoint: external NFT link open action
- Attacker controls: HTML/SVG/media content rendered in preview; after a profile switch
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
