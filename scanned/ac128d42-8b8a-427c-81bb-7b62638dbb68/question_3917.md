# Q3917: nft-metadata via NFTTransferConfirmationDialog 3917

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `NFTTransferConfirmationDialog` (packages/gui/src/components/nfts/NFTTransferConfirmationDialog.tsx) control objectionable-content flags and hidden NFT state with a duplicate identifier and drive the sequence preview -> mutate controlled state -> confirm so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTTransferConfirmationDialog.tsx` / `NFTTransferConfirmationDialog`
- Entrypoint: multiple NFT download action
- Attacker controls: objectionable-content flags and hidden NFT state; with a duplicate identifier
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
