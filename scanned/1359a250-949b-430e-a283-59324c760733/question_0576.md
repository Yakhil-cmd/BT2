# Q576: nft-metadata via SelectedActionsDialog 576

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `SelectedActionsDialog` (packages/gui/src/components/nfts/gallery/SelectedActionsDialog.tsx) control HTML/SVG/media content rendered in preview with a duplicate identifier and drive the sequence open notification -> resolve details -> execute so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/SelectedActionsDialog.tsx` / `SelectedActionsDialog`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; with a duplicate identifier
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
