# Q1087: nft-metadata via handleClose 1087

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `handleClose` (packages/gui/src/components/nfts/NFTBurnDialog.tsx) control filename and MIME/type mismatch during download with reordered RPC events and drive the sequence select -> edit backing object -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTBurnDialog.tsx` / `handleClose`
- Entrypoint: NFT preview dialog
- Attacker controls: filename and MIME/type mismatch during download; with reordered RPC events
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
