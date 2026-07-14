# Q3412: pool-plotnft via methods 3412

## Question
Can an unprivileged attacker entering through the pool join/change flow in `methods` (packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx) control external pool metadata changing between preview and submit with a duplicate identifier and drive the sequence download or render content -> trigger linked wallet action so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx` / `methods`
- Entrypoint: pool join/change flow
- Attacker controls: external pool metadata changing between preview and submit; with a duplicate identifier
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
