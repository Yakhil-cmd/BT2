# Q1468: nft-metadata via useNFTCoinUpdated 1468

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `useNFTCoinUpdated` (packages/api-react/src/hooks/useNFTCoinUpdated.ts) control content hash/status fields that change across fetches with a duplicate identifier and drive the sequence download or render content -> trigger linked wallet action so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinUpdated.ts` / `useNFTCoinUpdated`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; with a duplicate identifier
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
