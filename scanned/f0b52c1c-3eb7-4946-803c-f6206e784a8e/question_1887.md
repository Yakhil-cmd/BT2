# Q1887: nft-metadata via newDID 1887

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `newDID` (packages/gui/src/components/nfts/NFTMoveToProfileDialog.tsx) control objectionable-content flags and hidden NFT state with a duplicate identifier and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTMoveToProfileDialog.tsx` / `newDID`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: objectionable-content flags and hidden NFT state; with a duplicate identifier
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
