# Q873: pool-plotnft via aggregatePoints 873

## Question
Can an unprivileged attacker entering through the farmer reward address management in `aggregatePoints` (packages/gui/src/components/plotNFT/PlotNFTGraph.tsx) control pool URL/login response with mismatched launcher ID during a pending modal confirmation and drive the sequence connect -> approve -> switch context -> execute so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTGraph.tsx` / `aggregatePoints`
- Entrypoint: farmer reward address management
- Attacker controls: pool URL/login response with mismatched launcher ID; during a pending modal confirmation
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
