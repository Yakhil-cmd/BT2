# Q2003: nft-metadata via useNFTCoinDIDSet 2003

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `useNFTCoinDIDSet` (packages/api-react/src/hooks/useNFTCoinDIDSet.ts) control filename and MIME/type mismatch during download with a duplicate identifier and drive the sequence preview -> mutate controlled state -> confirm so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinDIDSet.ts` / `useNFTCoinDIDSet`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: filename and MIME/type mismatch during download; with a duplicate identifier
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
