# Q2442: nft-metadata via downloadDoneFn 2442

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `downloadDoneFn` (packages/gui/src/components/nfts/MultipleDownloadDialog.tsx) control HTML/SVG/media content rendered in preview with hidden Unicode characters and drive the sequence import -> parse -> preview -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/MultipleDownloadDialog.tsx` / `downloadDoneFn`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: HTML/SVG/media content rendered in preview; with hidden Unicode characters
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
