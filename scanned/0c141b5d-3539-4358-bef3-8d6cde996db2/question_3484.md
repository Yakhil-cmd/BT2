# Q3484: pool-plotnft via isLoading 3484

## Question
Can an unprivileged attacker entering through the pool join/change flow in `isLoading` (packages/gui/src/hooks/usePlotNFTs.ts) control pool URL/login response with mismatched launcher ID after a profile switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would route pool login links through unsafe external URL handling, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTs.ts` / `isLoading`
- Entrypoint: pool join/change flow
- Attacker controls: pool URL/login response with mismatched launcher ID; after a profile switch
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
