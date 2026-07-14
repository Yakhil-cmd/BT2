# Q3680: pool-plotnft via handleClick 3680

## Question
Can an unprivileged attacker entering through the pool join/change flow in `handleClick` (packages/gui/src/components/plotNFT/select/PlotNFTSelectFaucet.tsx) control stale PlotNFT wallet id during pool change with a stale Redux cache and drive the sequence select -> edit backing object -> submit so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/select/PlotNFTSelectFaucet.tsx` / `handleClick`
- Entrypoint: pool join/change flow
- Attacker controls: stale PlotNFT wallet id during pool change; with a stale Redux cache
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
