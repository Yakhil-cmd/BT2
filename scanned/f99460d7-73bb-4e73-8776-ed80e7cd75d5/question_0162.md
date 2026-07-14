# Q162: nft-metadata via NFTHashStatus 162

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `NFTHashStatus` (packages/gui/src/components/nfts/NFTHashStatus.tsx) control content hash/status fields that change across fetches with a stale Redux cache and drive the sequence open notification -> resolve details -> execute so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTHashStatus.tsx` / `NFTHashStatus`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; with a stale Redux cache
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
