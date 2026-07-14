# Q698: nft-metadata via getNFTsDataStatistics 698

## Question
Can an unprivileged attacker entering through the external NFT link open action in `getNFTsDataStatistics` (packages/gui/src/util/getNFTsDataStatistics.ts) control filename and MIME/type mismatch during download after a failed RPC response and drive the sequence select -> edit backing object -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/getNFTsDataStatistics.ts` / `getNFTsDataStatistics`
- Entrypoint: external NFT link open action
- Attacker controls: filename and MIME/type mismatch during download; after a failed RPC response
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
