# Q610: pool-plotnft via prepareSubmitData 610

## Question
Can an unprivileged attacker entering through the pool login link action in `prepareSubmitData` (packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx) control pool URL/login response with mismatched launcher ID with precision-boundary values and drive the sequence fetch -> cache -> refresh -> submit so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx` / `prepareSubmitData`
- Entrypoint: pool login link action
- Attacker controls: pool URL/login response with mismatched launcher ID; with precision-boundary values
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
