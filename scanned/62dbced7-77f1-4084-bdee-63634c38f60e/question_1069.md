# Q1069: nft-metadata via useNFTCoinDIDSet 1069

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `useNFTCoinDIDSet` (packages/api-react/src/hooks/useNFTCoinDIDSet.ts) control HTML/SVG/media content rendered in preview after a profile switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinDIDSet.ts` / `useNFTCoinDIDSet`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; after a profile switch
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
