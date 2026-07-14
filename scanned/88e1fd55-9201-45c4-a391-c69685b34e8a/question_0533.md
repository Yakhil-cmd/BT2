# Q533: nft-metadata via useNFTCoinRemoved 533

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `useNFTCoinRemoved` (packages/api-react/src/hooks/useNFTCoinRemoved.ts) control objectionable-content flags and hidden NFT state after a profile switch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinRemoved.ts` / `useNFTCoinRemoved`
- Entrypoint: NFT preview dialog
- Attacker controls: objectionable-content flags and hidden NFT state; after a profile switch
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
