# Q1509: nft-metadata via FilterPill 1509

## Question
Can an unprivileged attacker entering through the external NFT link open action in `FilterPill` (packages/gui/src/components/nfts/gallery/FilterPill.tsx) control HTML/SVG/media content rendered in preview with a stale Redux cache and drive the sequence validate input -> normalize payload -> call RPC so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/FilterPill.tsx` / `FilterPill`
- Entrypoint: external NFT link open action
- Attacker controls: HTML/SVG/media content rendered in preview; with a stale Redux cache
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
