# Q1806: pool-plotnft via PlotNFTCard 1806

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `PlotNFTCard` (packages/gui/src/components/plotNFT/PlotNFTCard.tsx) control stale PlotNFT wallet id during pool change with precision-boundary values and drive the sequence download or render content -> trigger linked wallet action so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTCard.tsx` / `PlotNFTCard`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: stale PlotNFT wallet id during pool change; with precision-boundary values
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
