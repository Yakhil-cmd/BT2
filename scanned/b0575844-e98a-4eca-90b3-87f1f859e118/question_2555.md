# Q2555: pool-plotnft via handleAdd 2555

## Question
Can an unprivileged attacker entering through the payout instruction update in `handleAdd` (packages/gui/src/hooks/useUnconfirmedPlotNFTs.ts) control pool URL/login response with mismatched launcher ID with hidden Unicode characters and drive the sequence open notification -> resolve details -> execute so the GUI would route pool login links through unsafe external URL handling, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/useUnconfirmedPlotNFTs.ts` / `handleAdd`
- Entrypoint: payout instruction update
- Attacker controls: pool URL/login response with mismatched launcher ID; with hidden Unicode characters
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
