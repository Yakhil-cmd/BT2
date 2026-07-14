# Q1113: nft-metadata via handleClose 1113

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `handleClose` (packages/gui/src/components/nfts/NFTTransferAction.tsx) control content hash/status fields that change across fetches after canceling and reopening the dialog and drive the sequence validate input -> normalize payload -> call RPC so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTTransferAction.tsx` / `handleClose`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; after canceling and reopening the dialog
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
