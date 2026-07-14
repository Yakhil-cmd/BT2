# Q3347: nft-metadata via NFTAttribute 3347

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `NFTAttribute` (packages/api/src/@types/NFTAttribute.ts) control HTML/SVG/media content rendered in preview with precision-boundary values and drive the sequence download or render content -> trigger linked wallet action so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/@types/NFTAttribute.ts` / `NFTAttribute`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: HTML/SVG/media content rendered in preview; with precision-boundary values
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
