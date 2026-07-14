# Q2447: nft-metadata via NotificationPreviewNFT 2447

## Question
Can an unprivileged attacker entering through the external NFT link open action in `NotificationPreviewNFT` (packages/gui/src/components/notification/NotificationPreviewNFT.tsx) control HTML/SVG/media content rendered in preview after a profile switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/notification/NotificationPreviewNFT.tsx` / `NotificationPreviewNFT`
- Entrypoint: external NFT link open action
- Attacker controls: HTML/SVG/media content rendered in preview; after a profile switch
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
