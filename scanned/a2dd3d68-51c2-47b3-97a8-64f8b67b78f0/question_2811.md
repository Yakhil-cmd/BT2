# Q2811: nft-metadata via getNftInfo 2811

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `getNftInfo` (packages/api/src/wallets/NFT.ts) control content hash/status fields that change across fetches with a redirected remote resource and drive the sequence validate input -> normalize payload -> call RPC so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/wallets/NFT.ts` / `getNftInfo`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; with a redirected remote resource
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
