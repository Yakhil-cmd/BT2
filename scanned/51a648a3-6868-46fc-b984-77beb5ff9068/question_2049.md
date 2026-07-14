# Q2049: nft-metadata via NFTTransferConfirmationDialog 2049

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `NFTTransferConfirmationDialog` (packages/gui/src/components/nfts/NFTTransferConfirmationDialog.tsx) control content hash/status fields that change across fetches through a batch of rapid user-accessible actions and drive the sequence validate input -> normalize payload -> call RPC so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTTransferConfirmationDialog.tsx` / `NFTTransferConfirmationDialog`
- Entrypoint: on-demand NFT data provider
- Attacker controls: content hash/status fields that change across fetches; through a batch of rapid user-accessible actions
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
