# Q2963: nft-metadata via value 2963

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `value` (packages/gui/src/components/nfts/NFTFilterProvider.tsx) control HTML/SVG/media content rendered in preview during a pending modal confirmation and drive the sequence connect -> approve -> switch context -> execute so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTFilterProvider.tsx` / `value`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; during a pending modal confirmation
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
