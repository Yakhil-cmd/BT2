# Q3485: pool-plotnft via poolInfo 3485

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `poolInfo` (packages/gui/src/hooks/usePoolInfo.ts) control external pool metadata changing between preview and submit after a profile switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would route pool login links through unsafe external URL handling, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePoolInfo.ts` / `poolInfo`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: external pool metadata changing between preview and submit; after a profile switch
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
