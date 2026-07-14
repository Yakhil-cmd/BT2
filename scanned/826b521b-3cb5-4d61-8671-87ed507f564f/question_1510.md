# Q1510: nft-metadata via showOrHide 1510

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `showOrHide` (packages/gui/src/components/nfts/gallery/SelectedActionsDialog.tsx) control filename and MIME/type mismatch during download after canceling and reopening the dialog and drive the sequence validate input -> normalize payload -> call RPC so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/SelectedActionsDialog.tsx` / `showOrHide`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: filename and MIME/type mismatch during download; after canceling and reopening the dialog
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
