# Q3471: nft-metadata via content 3471

## Question
Can an unprivileged attacker entering through the external NFT link open action in `content` (packages/gui/src/hooks/useNFTs.ts) control filename and MIME/type mismatch during download through a batch of rapid user-accessible actions and drive the sequence fetch -> cache -> refresh -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTs.ts` / `content`
- Entrypoint: external NFT link open action
- Attacker controls: filename and MIME/type mismatch during download; through a batch of rapid user-accessible actions
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
