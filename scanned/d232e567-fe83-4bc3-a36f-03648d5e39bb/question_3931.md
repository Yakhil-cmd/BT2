# Q3931: nft-metadata via subscribeToChanges 3931

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `subscribeToChanges` (packages/gui/src/components/nfts/provider/NFTProvider.tsx) control filename and MIME/type mismatch during download with a redirected remote resource and drive the sequence preview -> mutate controlled state -> confirm so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/NFTProvider.tsx` / `subscribeToChanges`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; with a redirected remote resource
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
