# Q534: nft-metadata via useNFTCoinUpdated 534

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `useNFTCoinUpdated` (packages/api-react/src/hooks/useNFTCoinUpdated.ts) control objectionable-content flags and hidden NFT state after a profile switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinUpdated.ts` / `useNFTCoinUpdated`
- Entrypoint: multiple NFT download action
- Attacker controls: objectionable-content flags and hidden NFT state; after a profile switch
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
