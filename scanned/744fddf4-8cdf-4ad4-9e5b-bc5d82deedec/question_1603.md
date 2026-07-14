# Q1603: nft-metadata via prepareNFTs 1603

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `prepareNFTs` (packages/gui/src/hooks/useNFTs.ts) control metadata URI list with mixed schemes and redirects after a network switch and drive the sequence select -> edit backing object -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTs.ts` / `prepareNFTs`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: metadata URI list with mixed schemes and redirects; after a network switch
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
