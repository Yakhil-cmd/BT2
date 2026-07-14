# Q1602: nft-metadata via verifyNFT 1602

## Question
Can an unprivileged attacker entering through the external NFT link open action in `verifyNFT` (packages/gui/src/hooks/useNFTVerifyHash.ts) control HTML/SVG/media content rendered in preview after canceling and reopening the dialog and drive the sequence connect -> approve -> switch context -> execute so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTVerifyHash.ts` / `verifyNFT`
- Entrypoint: external NFT link open action
- Attacker controls: HTML/SVG/media content rendered in preview; after canceling and reopening the dialog
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
