# Q2002: nft-metadata via useNFTCoinDIDSet 2002

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `useNFTCoinDIDSet` (packages/api-react/src/hooks/useNFTCoinDIDSet.ts) control filename and MIME/type mismatch during download with a delayed metadata fetch and drive the sequence download or render content -> trigger linked wallet action so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinDIDSet.ts` / `useNFTCoinDIDSet`
- Entrypoint: on-demand NFT data provider
- Attacker controls: filename and MIME/type mismatch during download; with a delayed metadata fetch
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
