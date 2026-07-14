# Q3379: nft-metadata via getNFTInbox 3379

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `getNFTInbox` (packages/gui/src/components/nfts/utils.ts) control HTML/SVG/media content rendered in preview through a batch of rapid user-accessible actions and drive the sequence preview -> mutate controlled state -> confirm so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/utils.ts` / `getNFTInbox`
- Entrypoint: on-demand NFT data provider
- Attacker controls: HTML/SVG/media content rendered in preview; through a batch of rapid user-accessible actions
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
