# Q1597: nft-metadata via events 1597

## Question
Can an unprivileged attacker entering through the external NFT link open action in `events` (packages/gui/src/hooks/useNFTCoinEvents.ts) control filename and MIME/type mismatch during download after canceling and reopening the dialog and drive the sequence load persisted state -> render approval -> execute command so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTCoinEvents.ts` / `events`
- Entrypoint: external NFT link open action
- Attacker controls: filename and MIME/type mismatch during download; after canceling and reopening the dialog
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
