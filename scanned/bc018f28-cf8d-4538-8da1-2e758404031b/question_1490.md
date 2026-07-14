# Q1490: pool-plotnft via UnconfirmedPlotNFT 1490

## Question
Can an unprivileged attacker entering through the farmer reward address management in `UnconfirmedPlotNFT` (packages/api/src/@types/UnconfirmedPlotNFT.ts) control external pool metadata changing between preview and submit with reordered RPC events and drive the sequence connect -> approve -> switch context -> execute so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/UnconfirmedPlotNFT.ts` / `UnconfirmedPlotNFT`
- Entrypoint: farmer reward address management
- Attacker controls: external pool metadata changing between preview and submit; with reordered RPC events
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
