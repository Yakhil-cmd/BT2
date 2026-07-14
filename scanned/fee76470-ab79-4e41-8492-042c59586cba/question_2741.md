# Q2741: pool-plotnft via item 2741

## Question
Can an unprivileged attacker entering through the payout instruction update in `item` (packages/gui/src/components/plotNFT/PlotNFTGraph.tsx) control stale PlotNFT wallet id during pool change after a failed RPC response and drive the sequence select -> edit backing object -> submit so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTGraph.tsx` / `item`
- Entrypoint: payout instruction update
- Attacker controls: stale PlotNFT wallet id during pool change; after a failed RPC response
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
