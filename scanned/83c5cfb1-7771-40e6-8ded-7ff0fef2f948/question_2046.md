# Q2046: nft-metadata via handleSubmit 2046

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `handleSubmit` (packages/gui/src/components/nfts/NFTTransferAction.tsx) control filename and MIME/type mismatch during download with a cached permission entry and drive the sequence download or render content -> trigger linked wallet action so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTTransferAction.tsx` / `handleSubmit`
- Entrypoint: on-demand NFT data provider
- Attacker controls: filename and MIME/type mismatch during download; with a cached permission entry
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
