# Q2360: pool-plotnft via usePlotNFTExternalDetails 2360

## Question
Can an unprivileged attacker entering through the pool join/change flow in `usePlotNFTExternalDetails` (packages/gui/src/hooks/usePlotNFTExternalDetails.ts) control payout address with network or Unicode ambiguity with case-normalized identifiers and drive the sequence validate input -> normalize payload -> call RPC so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTExternalDetails.ts` / `usePlotNFTExternalDetails`
- Entrypoint: pool join/change flow
- Attacker controls: payout address with network or Unicode ambiguity; with case-normalized identifiers
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
