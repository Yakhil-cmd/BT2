# Q2969: nft-metadata via NFTPreviewDialog 2969

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `NFTPreviewDialog` (packages/gui/src/components/nfts/NFTPreviewDialog.tsx) control metadata URI list with mixed schemes and redirects after a network switch and drive the sequence select -> edit backing object -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTPreviewDialog.tsx` / `NFTPreviewDialog`
- Entrypoint: NFT preview dialog
- Attacker controls: metadata URI list with mixed schemes and redirects; after a network switch
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
