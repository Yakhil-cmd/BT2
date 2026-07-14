# Q682: pool-plotnft via usePlotNFTs 682

## Question
Can an unprivileged attacker entering through the pool login link action in `usePlotNFTs` (packages/gui/src/hooks/usePlotNFTs.ts) control fee/reward amount near precision boundary after a network switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would route pool login links through unsafe external URL handling, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTs.ts` / `usePlotNFTs`
- Entrypoint: pool login link action
- Attacker controls: fee/reward amount near precision boundary; after a network switch
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
