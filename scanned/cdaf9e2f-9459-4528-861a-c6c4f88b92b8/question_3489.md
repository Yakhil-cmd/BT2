# Q3489: pool-plotnft via handleRemove 3489

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `handleRemove` (packages/gui/src/hooks/useUnconfirmedPlotNFTs.ts) control external pool metadata changing between preview and submit after a failed RPC response and drive the sequence preview -> mutate controlled state -> confirm so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/useUnconfirmedPlotNFTs.ts` / `handleRemove`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: external pool metadata changing between preview and submit; after a failed RPC response
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
