# Q1088: nft-metadata via nftId 1088

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `nftId` (packages/gui/src/components/nfts/NFTCard.tsx) control HTML/SVG/media content rendered in preview with a redirected remote resource and drive the sequence load persisted state -> render approval -> execute command so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTCard.tsx` / `nftId`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; with a redirected remote resource
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
