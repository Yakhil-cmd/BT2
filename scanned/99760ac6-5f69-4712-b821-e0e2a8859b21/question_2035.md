# Q2035: nft-metadata via NFTPreviewDialog 2035

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `NFTPreviewDialog` (packages/gui/src/components/nfts/NFTPreviewDialog.tsx) control objectionable-content flags and hidden NFT state after a failed RPC response and drive the sequence connect -> approve -> switch context -> execute so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTPreviewDialog.tsx` / `NFTPreviewDialog`
- Entrypoint: multiple NFT download action
- Attacker controls: objectionable-content flags and hidden NFT state; after a failed RPC response
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
