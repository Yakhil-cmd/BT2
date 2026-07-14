# Q2702: pool-plotnft via PoolJoin 2702

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `PoolJoin` (packages/gui/src/components/pool/PoolJoin.tsx) control fee/reward amount near precision boundary after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolJoin.tsx` / `PoolJoin`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: fee/reward amount near precision boundary; after a network switch
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
