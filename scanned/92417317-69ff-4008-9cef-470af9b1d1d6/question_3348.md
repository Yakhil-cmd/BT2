# Q3348: nft-metadata via NFTInfo 3348

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `NFTInfo` (packages/api/src/@types/NFTInfo.ts) control HTML/SVG/media content rendered in preview after a network switch and drive the sequence select -> edit backing object -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/@types/NFTInfo.ts` / `NFTInfo`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; after a network switch
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
