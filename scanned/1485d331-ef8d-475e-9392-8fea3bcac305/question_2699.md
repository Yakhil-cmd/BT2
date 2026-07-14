# Q2699: pool-plotnft via PoolHeader 2699

## Question
Can an unprivileged attacker entering through the pool join/change flow in `PoolHeader` (packages/gui/src/components/pool/PoolHeader.tsx) control external pool metadata changing between preview and submit with reordered RPC events and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolHeader.tsx` / `PoolHeader`
- Entrypoint: pool join/change flow
- Attacker controls: external pool metadata changing between preview and submit; with reordered RPC events
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
