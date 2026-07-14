# Q2531: nft-metadata via const 2531

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `const` (packages/gui/src/hooks/useNFTCoinEvents.ts) control filename and MIME/type mismatch during download with a stale Redux cache and drive the sequence download or render content -> trigger linked wallet action so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTCoinEvents.ts` / `const`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; with a stale Redux cache
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
