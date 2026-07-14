# Q2528: nft-metadata via handleIsNFTHidden 2528

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `handleIsNFTHidden` (packages/gui/src/hooks/useHiddenNFTs.ts) control objectionable-content flags and hidden NFT state through a batch of rapid user-accessible actions and drive the sequence import -> parse -> preview -> submit so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useHiddenNFTs.ts` / `handleIsNFTHidden`
- Entrypoint: NFT preview dialog
- Attacker controls: objectionable-content flags and hidden NFT state; through a batch of rapid user-accessible actions
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
