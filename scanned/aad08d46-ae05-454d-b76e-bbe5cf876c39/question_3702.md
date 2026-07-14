# Q3702: pool-plotnft via if 3702

## Question
Can an unprivileged attacker entering through the payout instruction update in `if` (packages/gui/src/hooks/useFarmerStatus.ts) control pool URL/login response with mismatched launcher ID with case-normalized identifiers and drive the sequence validate input -> normalize payload -> call RPC so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/useFarmerStatus.ts` / `if`
- Entrypoint: payout instruction update
- Attacker controls: pool URL/login response with mismatched launcher ID; with case-normalized identifiers
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
