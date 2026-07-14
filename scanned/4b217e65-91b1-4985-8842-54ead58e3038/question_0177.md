# Q177: nft-metadata via NFTTitle 177

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `NFTTitle` (packages/gui/src/components/nfts/NFTTitle.tsx) control content hash/status fields that change across fetches after a failed RPC response and drive the sequence import -> parse -> preview -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTTitle.tsx` / `NFTTitle`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; after a failed RPC response
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
