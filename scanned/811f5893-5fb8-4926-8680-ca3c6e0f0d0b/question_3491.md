# Q3491: nft-metadata via handleViewNFTOnExplorer 3491

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `handleViewNFTOnExplorer` (packages/gui/src/hooks/useViewNFTOnExplorer.ts) control content hash/status fields that change across fetches after canceling and reopening the dialog and drive the sequence import -> parse -> preview -> submit so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useViewNFTOnExplorer.ts` / `handleViewNFTOnExplorer`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; after canceling and reopening the dialog
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
