# Q577: nft-metadata via getNFTInbox 577

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `getNFTInbox` (packages/gui/src/components/nfts/utils.ts) control filename and MIME/type mismatch during download after a failed RPC response and drive the sequence open notification -> resolve details -> execute so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/utils.ts` / `getNFTInbox`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; after a failed RPC response
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
