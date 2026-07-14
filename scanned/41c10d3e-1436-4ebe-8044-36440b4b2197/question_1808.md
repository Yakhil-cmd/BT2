# Q1808: pool-plotnft via PlotNFTName 1808

## Question
Can an unprivileged attacker entering through the pool login link action in `PlotNFTName` (packages/gui/src/components/plotNFT/PlotNFTName.tsx) control fee/reward amount near precision boundary with precision-boundary values and drive the sequence preview -> mutate controlled state -> confirm so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTName.tsx` / `PlotNFTName`
- Entrypoint: pool login link action
- Attacker controls: fee/reward amount near precision boundary; with precision-boundary values
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
