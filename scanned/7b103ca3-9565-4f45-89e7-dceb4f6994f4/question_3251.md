# Q3251: nft-metadata via handleResolve 3251

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `handleResolve` (packages/gui/src/electron/utils/fetchJSON.ts) control content hash/status fields that change across fetches during a pending modal confirmation and drive the sequence fetch -> cache -> refresh -> submit so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/electron/utils/fetchJSON.ts` / `handleResolve`
- Entrypoint: on-demand NFT data provider
- Attacker controls: content hash/status fields that change across fetches; during a pending modal confirmation
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
