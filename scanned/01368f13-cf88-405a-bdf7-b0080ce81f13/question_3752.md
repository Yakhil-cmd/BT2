# Q3752: nft-metadata via NFTMetadata 3752

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `NFTMetadata` (packages/gui/src/components/nfts/NFTMetadata.tsx) control content hash/status fields that change across fetches with a delayed metadata fetch and drive the sequence download or render content -> trigger linked wallet action so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTMetadata.tsx` / `NFTMetadata`
- Entrypoint: on-demand NFT data provider
- Attacker controls: content hash/status fields that change across fetches; with a delayed metadata fetch
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
