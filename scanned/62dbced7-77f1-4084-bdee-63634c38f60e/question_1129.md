# Q1129: nft-metadata via const 1129

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `const` (packages/gui/src/components/nfts/provider/NFTProvider.tsx) control content hash/status fields that change across fetches with a cached permission entry and drive the sequence import -> parse -> preview -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/NFTProvider.tsx` / `const`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: content hash/status fields that change across fetches; with a cached permission entry
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
