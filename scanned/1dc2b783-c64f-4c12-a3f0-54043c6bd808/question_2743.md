# Q2743: pool-plotnft via PlotNFTState 2743

## Question
Can an unprivileged attacker entering through the farmer reward address management in `PlotNFTState` (packages/gui/src/components/plotNFT/PlotNFTState.tsx) control payout address with network or Unicode ambiguity after a failed RPC response and drive the sequence connect -> approve -> switch context -> execute so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTState.tsx` / `PlotNFTState`
- Entrypoint: farmer reward address management
- Attacker controls: payout address with network or Unicode ambiguity; after a failed RPC response
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
