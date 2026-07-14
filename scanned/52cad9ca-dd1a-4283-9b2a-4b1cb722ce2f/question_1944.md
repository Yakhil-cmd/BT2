# Q1944: nft-metadata via nftGetInfo 1944

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `nftGetInfo` (packages/gui/src/electron/api/nftGetInfo.ts) control HTML/SVG/media content rendered in preview after canceling and reopening the dialog and drive the sequence download or render content -> trigger linked wallet action so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/electron/api/nftGetInfo.ts` / `nftGetInfo`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; after canceling and reopening the dialog
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
