# Q666: nft-metadata via useNFTImageFittingMode 666

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `useNFTImageFittingMode` (packages/gui/src/hooks/useNFTImageFittingMode.tsx) control filename and MIME/type mismatch during download after a failed RPC response and drive the sequence fetch -> cache -> refresh -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTImageFittingMode.tsx` / `useNFTImageFittingMode`
- Entrypoint: on-demand NFT data provider
- Attacker controls: filename and MIME/type mismatch during download; after a failed RPC response
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
