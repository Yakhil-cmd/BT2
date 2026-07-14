# Q1616: pool-plotnft via isLoading 1616

## Question
Can an unprivileged attacker entering through the payout instruction update in `isLoading` (packages/gui/src/hooks/usePlotNFTs.ts) control stale PlotNFT wallet id during pool change with precision-boundary values and drive the sequence fetch -> cache -> refresh -> submit so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTs.ts` / `isLoading`
- Entrypoint: payout instruction update
- Attacker controls: stale PlotNFT wallet id during pool change; with precision-boundary values
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
