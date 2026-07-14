# Q2525: nft-metadata via useFetchAndProcessMetadata 2525

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `useFetchAndProcessMetadata` (packages/gui/src/hooks/useFetchAndProcessMetadata.ts) control HTML/SVG/media content rendered in preview with case-normalized identifiers and drive the sequence preview -> mutate controlled state -> confirm so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useFetchAndProcessMetadata.ts` / `useFetchAndProcessMetadata`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; with case-normalized identifiers
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
