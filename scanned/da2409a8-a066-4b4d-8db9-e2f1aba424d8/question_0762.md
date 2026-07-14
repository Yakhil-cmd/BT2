# Q762: pool-plotnft via HarvesterPlotsPaginated 762

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `HarvesterPlotsPaginated` (packages/api/src/@types/HarvesterPlotsPaginated.ts) control payout address with network or Unicode ambiguity with precision-boundary values and drive the sequence import -> parse -> preview -> submit so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/HarvesterPlotsPaginated.ts` / `HarvesterPlotsPaginated`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: payout address with network or Unicode ambiguity; with precision-boundary values
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
