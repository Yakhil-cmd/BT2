# Q3500: nft-metadata via getNFTsDataStatistics 3500

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `getNFTsDataStatistics` (packages/gui/src/util/getNFTsDataStatistics.ts) control HTML/SVG/media content rendered in preview through a batch of rapid user-accessible actions and drive the sequence preview -> mutate controlled state -> confirm so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/getNFTsDataStatistics.ts` / `getNFTsDataStatistics`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: HTML/SVG/media content rendered in preview; through a batch of rapid user-accessible actions
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
