# Q485: nft-metadata via useNFTMetadata 485

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `useNFTMetadata` (packages/gui/src/hooks/useNFTMetadata.ts) control metadata URI list with mixed schemes and redirects with reordered RPC events and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTMetadata.ts` / `useNFTMetadata`
- Entrypoint: on-demand NFT data provider
- Attacker controls: metadata URI list with mixed schemes and redirects; with reordered RPC events
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
