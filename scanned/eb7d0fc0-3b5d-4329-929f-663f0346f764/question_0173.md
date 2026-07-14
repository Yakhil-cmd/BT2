# Q173: nft-metadata via BorderLinearProgress 173

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `BorderLinearProgress` (packages/gui/src/components/nfts/NFTRankings.tsx) control HTML/SVG/media content rendered in preview with a cached permission entry and drive the sequence fetch -> cache -> refresh -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTRankings.tsx` / `BorderLinearProgress`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: HTML/SVG/media content rendered in preview; with a cached permission entry
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
