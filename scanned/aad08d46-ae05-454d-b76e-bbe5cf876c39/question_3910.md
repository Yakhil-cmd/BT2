# Q3910: nft-metadata via if 3910

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `if` (packages/gui/src/components/nfts/NFTSummary.tsx) control metadata URI list with mixed schemes and redirects after a network switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTSummary.tsx` / `if`
- Entrypoint: NFT preview dialog
- Attacker controls: metadata URI list with mixed schemes and redirects; after a network switch
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
