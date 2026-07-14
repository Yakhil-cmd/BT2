# Q1539: pool-plotnft via normalizePoolState 1539

## Question
Can an unprivileged attacker entering through the pool login link action in `normalizePoolState` (packages/core/src/utils/normalizePoolState.ts) control pool URL/login response with mismatched launcher ID with hidden Unicode characters and drive the sequence validate input -> normalize payload -> call RPC so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/core/src/utils/normalizePoolState.ts` / `normalizePoolState`
- Entrypoint: pool login link action
- Attacker controls: pool URL/login response with mismatched launcher ID; with hidden Unicode characters
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
