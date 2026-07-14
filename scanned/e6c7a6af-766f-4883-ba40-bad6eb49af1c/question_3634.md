# Q3634: pool-plotnft via handleJoinPool 3634

## Question
Can an unprivileged attacker entering through the pool login link action in `handleJoinPool` (packages/gui/src/components/pool/PoolHero.tsx) control pool URL/login response with mismatched launcher ID with precision-boundary values and drive the sequence fetch -> cache -> refresh -> submit so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolHero.tsx` / `handleJoinPool`
- Entrypoint: pool login link action
- Attacker controls: pool URL/login response with mismatched launcher ID; with precision-boundary values
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
