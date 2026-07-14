# Q3376: nft-metadata via unsubscribeDownloadDone 3376

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `unsubscribeDownloadDone` (packages/gui/src/components/nfts/MultipleDownloadDialog.tsx) control filename and MIME/type mismatch during download after a failed RPC response and drive the sequence connect -> approve -> switch context -> execute so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/MultipleDownloadDialog.tsx` / `unsubscribeDownloadDone`
- Entrypoint: on-demand NFT data provider
- Attacker controls: filename and MIME/type mismatch during download; after a failed RPC response
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
