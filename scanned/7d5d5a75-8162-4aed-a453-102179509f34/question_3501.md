# Q3501: pool-plotnft via getPoolInfo 3501

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `getPoolInfo` (packages/gui/src/util/getPoolInfo.ts) control stale PlotNFT wallet id during pool change after a network switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/util/getPoolInfo.ts` / `getPoolInfo`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: stale PlotNFT wallet id during pool change; after a network switch
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
