# Q2987: nft-metadata via position 2987

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `position` (packages/gui/src/components/nfts/detail/NFTDetailV2.tsx) control filename and MIME/type mismatch during download with a duplicate identifier and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/detail/NFTDetailV2.tsx` / `position`
- Entrypoint: NFT preview dialog
- Attacker controls: filename and MIME/type mismatch during download; with a duplicate identifier
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
