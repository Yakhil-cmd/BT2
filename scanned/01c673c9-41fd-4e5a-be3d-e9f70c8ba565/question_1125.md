# Q1125: nft-metadata via context 1125

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `context` (packages/gui/src/components/nfts/gallery/NFTGalleryScrollPositionProvider.tsx) control content hash/status fields that change across fetches during a pending modal confirmation and drive the sequence fetch -> cache -> refresh -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGalleryScrollPositionProvider.tsx` / `context`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; during a pending modal confirmation
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
