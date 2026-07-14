# Q2744: pool-plotnft via PlotNFTUnconfirmedCard 2744

## Question
Can an unprivileged attacker entering through the pool join/change flow in `PlotNFTUnconfirmedCard` (packages/gui/src/components/plotNFT/PlotNFTUnconfirmedCard.tsx) control payout address with network or Unicode ambiguity with precision-boundary values and drive the sequence fetch -> cache -> refresh -> submit so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTUnconfirmedCard.tsx` / `PlotNFTUnconfirmedCard`
- Entrypoint: pool join/change flow
- Attacker controls: payout address with network or Unicode ambiguity; with precision-boundary values
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
