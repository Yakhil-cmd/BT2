# Q3636: pool-plotnft via handleJoinPool 3636

## Question
Can an unprivileged attacker entering through the pool join/change flow in `handleJoinPool` (packages/gui/src/components/pool/PoolJoin.tsx) control pool URL/login response with mismatched launcher ID with precision-boundary values and drive the sequence fetch -> cache -> refresh -> submit so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolJoin.tsx` / `handleJoinPool`
- Entrypoint: pool join/change flow
- Attacker controls: pool URL/login response with mismatched launcher ID; with precision-boundary values
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
