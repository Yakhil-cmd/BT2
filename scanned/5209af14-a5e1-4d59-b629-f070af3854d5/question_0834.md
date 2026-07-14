# Q834: pool-plotnft via PoolJoin 834

## Question
Can an unprivileged attacker entering through the pool login link action in `PoolJoin` (packages/gui/src/components/pool/PoolJoin.tsx) control pool URL/login response with mismatched launcher ID with hidden Unicode characters and drive the sequence connect -> approve -> switch context -> execute so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolJoin.tsx` / `PoolJoin`
- Entrypoint: pool login link action
- Attacker controls: pool URL/login response with mismatched launcher ID; with hidden Unicode characters
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
