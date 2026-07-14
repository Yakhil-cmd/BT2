# Q493: pool-plotnft via usePlotNFTExternalDetails 493

## Question
Can an unprivileged attacker entering through the pool login link action in `usePlotNFTExternalDetails` (packages/gui/src/hooks/usePlotNFTExternalDetails.ts) control external pool metadata changing between preview and submit with a cached permission entry and drive the sequence connect -> approve -> switch context -> execute so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTExternalDetails.ts` / `usePlotNFTExternalDetails`
- Entrypoint: pool login link action
- Attacker controls: external pool metadata changing between preview and submit; with a cached permission entry
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
