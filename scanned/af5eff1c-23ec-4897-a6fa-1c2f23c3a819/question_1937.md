# Q1937: nft-metadata via checkNFTOwnership 1937

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `checkNFTOwnership` (packages/gui/src/electron/api/checkNFTOwnership.ts) control HTML/SVG/media content rendered in preview after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/electron/api/checkNFTOwnership.ts` / `checkNFTOwnership`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; after a network switch
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
