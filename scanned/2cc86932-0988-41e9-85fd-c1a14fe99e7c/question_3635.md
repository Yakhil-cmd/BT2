# Q3635: pool-plotnft via rows 3635

## Question
Can an unprivileged attacker entering through the farmer reward address management in `rows` (packages/gui/src/components/pool/PoolInfo.tsx) control pool URL/login response with mismatched launcher ID with precision-boundary values and drive the sequence fetch -> cache -> refresh -> submit so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolInfo.tsx` / `rows`
- Entrypoint: farmer reward address management
- Attacker controls: pool URL/login response with mismatched launcher ID; with precision-boundary values
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
