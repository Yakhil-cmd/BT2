# Q1617: pool-plotnft via poolInfo 1617

## Question
Can an unprivileged attacker entering through the pool login link action in `poolInfo` (packages/gui/src/hooks/usePoolInfo.ts) control payout address with network or Unicode ambiguity with precision-boundary values and drive the sequence connect -> approve -> switch context -> execute so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePoolInfo.ts` / `poolInfo`
- Entrypoint: pool login link action
- Attacker controls: payout address with network or Unicode ambiguity; with precision-boundary values
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
