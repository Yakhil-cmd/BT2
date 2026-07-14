# Q3367: pool-plotnft via PlotNFTState 3367

## Question
Can an unprivileged attacker entering through the pool login link action in `PlotNFTState` (packages/api/src/constants/PlotNFTState.ts) control external pool metadata changing between preview and submit through a batch of rapid user-accessible actions and drive the sequence preview -> mutate controlled state -> confirm so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/constants/PlotNFTState.ts` / `PlotNFTState`
- Entrypoint: pool login link action
- Attacker controls: external pool metadata changing between preview and submit; through a batch of rapid user-accessible actions
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
