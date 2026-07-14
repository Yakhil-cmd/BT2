# Q1633: pool-plotnft via getPoolInfo 1633

## Question
Can an unprivileged attacker entering through the pool login link action in `getPoolInfo` (packages/gui/src/util/getPoolInfo.ts) control pool URL/login response with mismatched launcher ID with hidden Unicode characters and drive the sequence validate input -> normalize payload -> call RPC so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/util/getPoolInfo.ts` / `getPoolInfo`
- Entrypoint: pool login link action
- Attacker controls: pool URL/login response with mismatched launcher ID; with hidden Unicode characters
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
