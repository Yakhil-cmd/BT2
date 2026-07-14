# Q2934: nft-metadata via nftWallets 2934

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `nftWallets` (packages/api-react/src/hooks/useGetNFTWallets.ts) control HTML/SVG/media content rendered in preview with conflicting localStorage preferences and drive the sequence open notification -> resolve details -> execute so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useGetNFTWallets.ts` / `nftWallets`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; with conflicting localStorage preferences
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
