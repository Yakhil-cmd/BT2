# Q2000: nft-metadata via useGetNFTWallets 2000

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `useGetNFTWallets` (packages/api-react/src/hooks/useGetNFTWallets.ts) control HTML/SVG/media content rendered in preview with a delayed metadata fetch and drive the sequence download or render content -> trigger linked wallet action so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useGetNFTWallets.ts` / `useGetNFTWallets`
- Entrypoint: multiple NFT download action
- Attacker controls: HTML/SVG/media content rendered in preview; with a delayed metadata fetch
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
