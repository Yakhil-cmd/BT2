# Q2548: pool-plotnft via usePlotNFTDetails 2548

## Question
Can an unprivileged attacker entering through the pool join/change flow in `usePlotNFTDetails` (packages/gui/src/hooks/usePlotNFTDetails.ts) control payout address with network or Unicode ambiguity after a network switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTDetails.ts` / `usePlotNFTDetails`
- Entrypoint: pool join/change flow
- Attacker controls: payout address with network or Unicode ambiguity; after a network switch
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
