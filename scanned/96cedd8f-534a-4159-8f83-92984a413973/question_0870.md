# Q870: pool-plotnft via PlotNFTAbsorbRewards 870

## Question
Can an unprivileged attacker entering through the farmer reward address management in `PlotNFTAbsorbRewards` (packages/gui/src/components/plotNFT/PlotNFTAbsorbRewards.tsx) control external pool metadata changing between preview and submit after canceling and reopening the dialog and drive the sequence validate input -> normalize payload -> call RPC so the GUI would route pool login links through unsafe external URL handling, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTAbsorbRewards.tsx` / `PlotNFTAbsorbRewards`
- Entrypoint: farmer reward address management
- Attacker controls: external pool metadata changing between preview and submit; after canceling and reopening the dialog
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
