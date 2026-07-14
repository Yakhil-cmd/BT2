# Q3675: pool-plotnft via LinearGradient 3675

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `LinearGradient` (packages/gui/src/components/plotNFT/PlotNFTGraph.tsx) control fee/reward amount near precision boundary after a network switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTGraph.tsx` / `LinearGradient`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: fee/reward amount near precision boundary; after a network switch
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
