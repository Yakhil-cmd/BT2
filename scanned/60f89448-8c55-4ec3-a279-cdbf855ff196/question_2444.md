# Q2444: nft-metadata via SelectedActionsDialog 2444

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `SelectedActionsDialog` (packages/gui/src/components/nfts/gallery/SelectedActionsDialog.tsx) control metadata URI list with mixed schemes and redirects with a stale Redux cache and drive the sequence load persisted state -> render approval -> execute command so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/SelectedActionsDialog.tsx` / `SelectedActionsDialog`
- Entrypoint: on-demand NFT data provider
- Attacker controls: metadata URI list with mixed schemes and redirects; with a stale Redux cache
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
