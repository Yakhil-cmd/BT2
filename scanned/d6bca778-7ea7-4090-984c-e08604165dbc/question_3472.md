# Q3472: nft-metadata via nachoNFTIDs 3472

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `nachoNFTIDs` (packages/gui/src/hooks/useNachoNFTs.ts) control filename and MIME/type mismatch during download after a profile switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNachoNFTs.ts` / `nachoNFTIDs`
- Entrypoint: on-demand NFT data provider
- Attacker controls: filename and MIME/type mismatch during download; after a profile switch
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
