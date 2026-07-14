# Q2566: nft-metadata via getNFTsDataStatistics 2566

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `getNFTsDataStatistics` (packages/gui/src/util/getNFTsDataStatistics.ts) control content hash/status fields that change across fetches with precision-boundary values and drive the sequence load persisted state -> render approval -> execute command so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/getNFTsDataStatistics.ts` / `getNFTsDataStatistics`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; with precision-boundary values
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
