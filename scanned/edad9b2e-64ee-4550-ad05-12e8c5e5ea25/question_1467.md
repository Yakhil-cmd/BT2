# Q1467: nft-metadata via useNFTCoinRemoved 1467

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `useNFTCoinRemoved` (packages/api-react/src/hooks/useNFTCoinRemoved.ts) control metadata URI list with mixed schemes and redirects with a duplicate identifier and drive the sequence download or render content -> trigger linked wallet action so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinRemoved.ts` / `useNFTCoinRemoved`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: metadata URI list with mixed schemes and redirects; with a duplicate identifier
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
