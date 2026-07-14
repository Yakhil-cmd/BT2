# Q2474: nft-metadata via totalPointsFound24 2474

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `totalPointsFound24` (packages/gui/src/components/plotNFT/PlotExternalNFTCard.tsx) control HTML/SVG/media content rendered in preview after canceling and reopening the dialog and drive the sequence load persisted state -> render approval -> execute command so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotExternalNFTCard.tsx` / `totalPointsFound24`
- Entrypoint: multiple NFT download action
- Attacker controls: HTML/SVG/media content rendered in preview; after canceling and reopening the dialog
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
