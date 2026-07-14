# Q1115: nft-metadata via NFTTransferConfirmationDialog 1115

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `NFTTransferConfirmationDialog` (packages/gui/src/components/nfts/NFTTransferConfirmationDialog.tsx) control metadata URI list with mixed schemes and redirects with precision-boundary values and drive the sequence select -> edit backing object -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTTransferConfirmationDialog.tsx` / `NFTTransferConfirmationDialog`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: metadata URI list with mixed schemes and redirects; with precision-boundary values
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
