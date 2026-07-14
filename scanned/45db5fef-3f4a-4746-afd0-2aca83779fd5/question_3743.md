# Q3743: nft-metadata via getNftWalletsWithDids 3743

## Question
Can an unprivileged attacker entering through the external NFT link open action in `getNftWalletsWithDids` (packages/api/src/wallets/NFT.ts) control filename and MIME/type mismatch during download during a pending modal confirmation and drive the sequence load persisted state -> render approval -> execute command so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/wallets/NFT.ts` / `getNftWalletsWithDids`
- Entrypoint: external NFT link open action
- Attacker controls: filename and MIME/type mismatch during download; during a pending modal confirmation
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
