# Q166: nft-metadata via NFTPreviewDialog 166

## Question
Can an unprivileged attacker entering through the external NFT link open action in `NFTPreviewDialog` (packages/gui/src/components/nfts/NFTPreviewDialog.tsx) control content hash/status fields that change across fetches with reordered RPC events and drive the sequence load persisted state -> render approval -> execute command so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTPreviewDialog.tsx` / `NFTPreviewDialog`
- Entrypoint: external NFT link open action
- Attacker controls: content hash/status fields that change across fetches; with reordered RPC events
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
