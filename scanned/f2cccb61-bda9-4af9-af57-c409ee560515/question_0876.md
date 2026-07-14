# Q876: pool-plotnft via PlotNFTUnconfirmedCard 876

## Question
Can an unprivileged attacker entering through the payout instruction update in `PlotNFTUnconfirmedCard` (packages/gui/src/components/plotNFT/PlotNFTUnconfirmedCard.tsx) control fee/reward amount near precision boundary after a failed RPC response and drive the sequence download or render content -> trigger linked wallet action so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTUnconfirmedCard.tsx` / `PlotNFTUnconfirmedCard`
- Entrypoint: payout instruction update
- Attacker controls: fee/reward amount near precision boundary; after a failed RPC response
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
