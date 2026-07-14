# Q2047: nft-metadata via handleSubmit 2047

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `handleSubmit` (packages/gui/src/components/nfts/NFTTransferAction.tsx) control objectionable-content flags and hidden NFT state with a stale Redux cache and drive the sequence download or render content -> trigger linked wallet action so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTTransferAction.tsx` / `handleSubmit`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: objectionable-content flags and hidden NFT state; with a stale Redux cache
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
