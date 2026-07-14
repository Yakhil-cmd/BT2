# Q2989: nft-metadata via toggleMultipleSelection 2989

## Question
Can an unprivileged attacker entering through the external NFT link open action in `toggleMultipleSelection` (packages/gui/src/components/nfts/gallery/NFTGallery.tsx) control objectionable-content flags and hidden NFT state with a duplicate identifier and drive the sequence connect -> approve -> switch context -> execute so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGallery.tsx` / `toggleMultipleSelection`
- Entrypoint: external NFT link open action
- Attacker controls: objectionable-content flags and hidden NFT state; with a duplicate identifier
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
