# Q3756: nft-metadata via nftWalletsWithoutDIDs 3756

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `nftWalletsWithoutDIDs` (packages/gui/src/components/nfts/NFTProfileDropdown.tsx) control HTML/SVG/media content rendered in preview through a batch of rapid user-accessible actions and drive the sequence download or render content -> trigger linked wallet action so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTProfileDropdown.tsx` / `nftWalletsWithoutDIDs`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: HTML/SVG/media content rendered in preview; through a batch of rapid user-accessible actions
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
