# Q196: nft-metadata via NFTProviderContext 196

## Question
Can an unprivileged attacker entering through the external NFT link open action in `NFTProviderContext` (packages/gui/src/components/nfts/provider/NFTProviderContext.ts) control filename and MIME/type mismatch during download with a stale Redux cache and drive the sequence fetch -> cache -> refresh -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/NFTProviderContext.ts` / `NFTProviderContext`
- Entrypoint: external NFT link open action
- Attacker controls: filename and MIME/type mismatch during download; with a stale Redux cache
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
