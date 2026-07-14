# Q579: nft-metadata via NotificationPreviewNFT 579

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `NotificationPreviewNFT` (packages/gui/src/components/notification/NotificationPreviewNFT.tsx) control objectionable-content flags and hidden NFT state with precision-boundary values and drive the sequence validate input -> normalize payload -> call RPC so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/notification/NotificationPreviewNFT.tsx` / `NotificationPreviewNFT`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: objectionable-content flags and hidden NFT state; with precision-boundary values
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
