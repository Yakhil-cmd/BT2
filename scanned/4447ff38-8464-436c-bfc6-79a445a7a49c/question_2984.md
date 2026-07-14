# Q2984: nft-metadata via NFTs 2984

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `NFTs` (packages/gui/src/components/nfts/NFTs.tsx) control filename and MIME/type mismatch during download with hidden Unicode characters and drive the sequence fetch -> cache -> refresh -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTs.tsx` / `NFTs`
- Entrypoint: on-demand NFT data provider
- Attacker controls: filename and MIME/type mismatch during download; with hidden Unicode characters
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
