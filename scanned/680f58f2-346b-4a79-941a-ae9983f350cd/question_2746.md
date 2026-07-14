# Q2746: pool-plotnft via PlotNFTSelectFaucet 2746

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `PlotNFTSelectFaucet` (packages/gui/src/components/plotNFT/select/PlotNFTSelectFaucet.tsx) control external pool metadata changing between preview and submit after canceling and reopening the dialog and drive the sequence preview -> mutate controlled state -> confirm so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/select/PlotNFTSelectFaucet.tsx` / `PlotNFTSelectFaucet`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: external pool metadata changing between preview and submit; after canceling and reopening the dialog
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
