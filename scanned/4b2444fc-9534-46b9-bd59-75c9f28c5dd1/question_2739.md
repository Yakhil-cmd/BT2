# Q2739: pool-plotnft via PlotNFTAdd 2739

## Question
Can an unprivileged attacker entering through the pool login link action in `PlotNFTAdd` (packages/gui/src/components/plotNFT/PlotNFTAdd.tsx) control stale PlotNFT wallet id during pool change with conflicting localStorage preferences and drive the sequence preview -> mutate controlled state -> confirm so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTAdd.tsx` / `PlotNFTAdd`
- Entrypoint: pool login link action
- Attacker controls: stale PlotNFT wallet id during pool change; with conflicting localStorage preferences
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
