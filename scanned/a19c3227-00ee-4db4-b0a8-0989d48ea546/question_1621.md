# Q1621: pool-plotnft via currentUnconfirmed 1621

## Question
Can an unprivileged attacker entering through the pool login link action in `currentUnconfirmed` (packages/gui/src/hooks/useUnconfirmedPlotNFTs.ts) control fee/reward amount near precision boundary during a pending modal confirmation and drive the sequence connect -> approve -> switch context -> execute so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/useUnconfirmedPlotNFTs.ts` / `currentUnconfirmed`
- Entrypoint: pool login link action
- Attacker controls: fee/reward amount near precision boundary; during a pending modal confirmation
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
