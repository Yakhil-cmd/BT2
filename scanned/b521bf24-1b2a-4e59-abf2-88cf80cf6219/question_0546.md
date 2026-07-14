# Q546: nft-metadata via NFTInfo 546

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `NFTInfo` (packages/api/src/@types/NFTInfo.ts) control filename and MIME/type mismatch during download during a pending modal confirmation and drive the sequence load persisted state -> render approval -> execute command so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/@types/NFTInfo.ts` / `NFTInfo`
- Entrypoint: on-demand NFT data provider
- Attacker controls: filename and MIME/type mismatch during download; during a pending modal confirmation
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
