# Q2755: nft-metadata via handleScalePreviewImages 2755

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `handleScalePreviewImages` (packages/gui/src/components/settings/SettingsNFT.tsx) control HTML/SVG/media content rendered in preview with a redirected remote resource and drive the sequence open notification -> resolve details -> execute so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/settings/SettingsNFT.tsx` / `handleScalePreviewImages`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; with a redirected remote resource
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
