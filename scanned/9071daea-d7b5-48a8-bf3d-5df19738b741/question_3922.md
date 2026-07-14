# Q3922: nft-metadata via toggleSensitiveContent 3922

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `toggleSensitiveContent` (packages/gui/src/components/nfts/gallery/NFTGallery.tsx) control objectionable-content flags and hidden NFT state after canceling and reopening the dialog and drive the sequence fetch -> cache -> refresh -> submit so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGallery.tsx` / `toggleSensitiveContent`
- Entrypoint: NFT preview dialog
- Attacker controls: objectionable-content flags and hidden NFT state; after canceling and reopening the dialog
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
