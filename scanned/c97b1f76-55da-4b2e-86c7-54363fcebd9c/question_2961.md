# Q2961: nft-metadata via NFTDetails 2961

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `NFTDetails` (packages/gui/src/components/nfts/NFTDetails.tsx) control content hash/status fields that change across fetches through a batch of rapid user-accessible actions and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTDetails.tsx` / `NFTDetails`
- Entrypoint: multiple NFT download action
- Attacker controls: content hash/status fields that change across fetches; through a batch of rapid user-accessible actions
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
