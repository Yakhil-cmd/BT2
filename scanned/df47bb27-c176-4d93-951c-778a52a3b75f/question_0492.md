# Q492: pool-plotnft via usePlotNFTExternalDetails 492

## Question
Can an unprivileged attacker entering through the payout instruction update in `usePlotNFTExternalDetails` (packages/gui/src/hooks/usePlotNFTExternalDetails.ts) control fee/reward amount near precision boundary with a cached permission entry and drive the sequence connect -> approve -> switch context -> execute so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTExternalDetails.ts` / `usePlotNFTExternalDetails`
- Entrypoint: payout instruction update
- Attacker controls: fee/reward amount near precision boundary; with a cached permission entry
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
