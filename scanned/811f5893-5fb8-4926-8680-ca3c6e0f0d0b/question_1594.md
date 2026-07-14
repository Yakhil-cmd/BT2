# Q1594: nft-metadata via handleSetIsHidden 1594

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `handleSetIsHidden` (packages/gui/src/hooks/useHiddenNFTs.ts) control filename and MIME/type mismatch during download with precision-boundary values and drive the sequence download or render content -> trigger linked wallet action so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useHiddenNFTs.ts` / `handleSetIsHidden`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; with precision-boundary values
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
