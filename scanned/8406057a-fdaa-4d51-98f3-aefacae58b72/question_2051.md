# Q2051: nft-metadata via NFTs 2051

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `NFTs` (packages/gui/src/components/nfts/NFTs.tsx) control HTML/SVG/media content rendered in preview during a pending modal confirmation and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTs.tsx` / `NFTs`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; during a pending modal confirmation
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
