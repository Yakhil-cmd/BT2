# Q1891: nft-metadata via events 1891

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `events` (packages/gui/src/components/nfts/provider/hooks/useMetadataData.ts) control content hash/status fields that change across fetches after a failed RPC response and drive the sequence import -> parse -> preview -> submit so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/hooks/useMetadataData.ts` / `events`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; after a failed RPC response
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
