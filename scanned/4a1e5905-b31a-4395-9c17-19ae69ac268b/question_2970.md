# Q2970: nft-metadata via if 2970

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `if` (packages/gui/src/components/nfts/NFTProgressBar.tsx) control content hash/status fields that change across fetches with a stale Redux cache and drive the sequence preview -> mutate controlled state -> confirm so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTProgressBar.tsx` / `if`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: content hash/status fields that change across fetches; with a stale Redux cache
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
