# Q3564: pool-plotnft via HarvesterPlotsPaginated 3564

## Question
Can an unprivileged attacker entering through the pool login link action in `HarvesterPlotsPaginated` (packages/api/src/@types/HarvesterPlotsPaginated.ts) control pool URL/login response with mismatched launcher ID with a delayed metadata fetch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/HarvesterPlotsPaginated.ts` / `HarvesterPlotsPaginated`
- Entrypoint: pool login link action
- Attacker controls: pool URL/login response with mismatched launcher ID; with a delayed metadata fetch
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
