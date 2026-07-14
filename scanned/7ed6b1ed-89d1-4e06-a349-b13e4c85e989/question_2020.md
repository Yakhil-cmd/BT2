# Q2020: nft-metadata via handleSubmit 2020

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `handleSubmit` (packages/gui/src/components/nfts/NFTBurnDialog.tsx) control metadata URI list with mixed schemes and redirects with case-normalized identifiers and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTBurnDialog.tsx` / `handleSubmit`
- Entrypoint: on-demand NFT data provider
- Attacker controls: metadata URI list with mixed schemes and redirects; with case-normalized identifiers
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
