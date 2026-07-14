# Q2476: pool-plotnft via PlotNFTExternalState 2476

## Question
Can an unprivileged attacker entering through the pool join/change flow in `PlotNFTExternalState` (packages/gui/src/components/plotNFT/PlotNFTExternalState.tsx) control pool URL/login response with mismatched launcher ID after a failed RPC response and drive the sequence preview -> mutate controlled state -> confirm so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTExternalState.tsx` / `PlotNFTExternalState`
- Entrypoint: pool join/change flow
- Attacker controls: pool URL/login response with mismatched launcher ID; after a failed RPC response
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
