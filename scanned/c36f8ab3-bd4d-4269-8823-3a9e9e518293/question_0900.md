# Q900: pool-plotnft via useFarmerStatus 900

## Question
Can an unprivileged attacker entering through the pool join/change flow in `useFarmerStatus` (packages/gui/src/hooks/useFarmerStatus.ts) control external pool metadata changing between preview and submit with conflicting localStorage preferences and drive the sequence select -> edit backing object -> submit so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/useFarmerStatus.ts` / `useFarmerStatus`
- Entrypoint: pool join/change flow
- Attacker controls: external pool metadata changing between preview and submit; with conflicting localStorage preferences
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
