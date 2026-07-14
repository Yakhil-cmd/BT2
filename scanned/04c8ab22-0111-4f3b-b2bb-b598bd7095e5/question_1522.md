# Q1522: nft-metadata via launcherId 1522

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `launcherId` (packages/gui/src/components/signVerify/SigningEntityNFT.tsx) control HTML/SVG/media content rendered in preview with a delayed metadata fetch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/signVerify/SigningEntityNFT.tsx` / `launcherId`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: HTML/SVG/media content rendered in preview; with a delayed metadata fetch
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
