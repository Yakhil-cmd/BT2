# Q2630: pool-plotnft via HarvesterPlotsPaginated 2630

## Question
Can an unprivileged attacker entering through the farmer reward address management in `HarvesterPlotsPaginated` (packages/api/src/@types/HarvesterPlotsPaginated.ts) control external pool metadata changing between preview and submit after a profile switch and drive the sequence open notification -> resolve details -> execute so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/HarvesterPlotsPaginated.ts` / `HarvesterPlotsPaginated`
- Entrypoint: farmer reward address management
- Attacker controls: external pool metadata changing between preview and submit; after a profile switch
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
