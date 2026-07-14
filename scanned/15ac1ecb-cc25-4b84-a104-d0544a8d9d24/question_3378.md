# Q3378: nft-metadata via showOrHide 3378

## Question
Can an unprivileged attacker entering through the external NFT link open action in `showOrHide` (packages/gui/src/components/nfts/gallery/SelectedActionsDialog.tsx) control metadata URI list with mixed schemes and redirects with a delayed metadata fetch and drive the sequence download or render content -> trigger linked wallet action so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/SelectedActionsDialog.tsx` / `showOrHide`
- Entrypoint: external NFT link open action
- Attacker controls: metadata URI list with mixed schemes and redirects; with a delayed metadata fetch
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
