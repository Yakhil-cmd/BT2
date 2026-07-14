# Q2041: nft-metadata via if 2041

## Question
Can an unprivileged attacker entering through the external NFT link open action in `if` (packages/gui/src/components/nfts/NFTRankings.tsx) control HTML/SVG/media content rendered in preview with case-normalized identifiers and drive the sequence load persisted state -> render approval -> execute command so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTRankings.tsx` / `if`
- Entrypoint: external NFT link open action
- Attacker controls: HTML/SVG/media content rendered in preview; with case-normalized identifiers
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
