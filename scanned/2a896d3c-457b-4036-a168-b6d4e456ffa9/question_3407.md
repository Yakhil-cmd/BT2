# Q3407: pool-plotnft via normalizePoolState 3407

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `normalizePoolState` (packages/core/src/utils/normalizePoolState.ts) control fee/reward amount near precision boundary after a network switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/core/src/utils/normalizePoolState.ts` / `normalizePoolState`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: fee/reward amount near precision boundary; after a network switch
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
