# Q1631: nft-metadata via getNFTId 1631

## Question
Can an unprivileged attacker entering through the external NFT link open action in `getNFTId` (packages/gui/src/util/getNFTId.ts) control content hash/status fields that change across fetches with a delayed metadata fetch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/getNFTId.ts` / `getNFTId`
- Entrypoint: external NFT link open action
- Attacker controls: content hash/status fields that change across fetches; with a delayed metadata fetch
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
