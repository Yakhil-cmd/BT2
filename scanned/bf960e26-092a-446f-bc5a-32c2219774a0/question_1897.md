# Q1897: nft-metadata via events 1897

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `events` (packages/gui/src/components/nfts/provider/hooks/useNFTDataOnDemand.ts) control filename and MIME/type mismatch during download after a profile switch and drive the sequence import -> parse -> preview -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/hooks/useNFTDataOnDemand.ts` / `events`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: filename and MIME/type mismatch during download; after a profile switch
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
