# Q875: pool-plotnft via PlotNFTState 875

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `PlotNFTState` (packages/gui/src/components/plotNFT/PlotNFTState.tsx) control fee/reward amount near precision boundary during a pending modal confirmation and drive the sequence download or render content -> trigger linked wallet action so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTState.tsx` / `PlotNFTState`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: fee/reward amount near precision boundary; during a pending modal confirmation
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
