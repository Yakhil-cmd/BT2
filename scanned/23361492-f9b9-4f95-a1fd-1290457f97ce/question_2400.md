# Q2400: nft-metadata via useNFTCoinAdded 2400

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `useNFTCoinAdded` (packages/api-react/src/hooks/useNFTCoinAdded.ts) control objectionable-content flags and hidden NFT state with case-normalized identifiers and drive the sequence download or render content -> trigger linked wallet action so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinAdded.ts` / `useNFTCoinAdded`
- Entrypoint: NFT preview dialog
- Attacker controls: objectionable-content flags and hidden NFT state; with case-normalized identifiers
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
