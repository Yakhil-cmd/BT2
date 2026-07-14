# Q3859: nft-metadata via isValidNFTId 3859

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `isValidNFTId` (packages/gui/src/util/nfts.ts) control filename and MIME/type mismatch during download after canceling and reopening the dialog and drive the sequence load persisted state -> render approval -> execute command so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/nfts.ts` / `isValidNFTId`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; after canceling and reopening the dialog
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
