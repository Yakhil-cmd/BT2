# Q2697: pool-plotnft via Pool 2697

## Question
Can an unprivileged attacker entering through the payout instruction update in `Pool` (packages/gui/src/components/pool/Pool.tsx) control stale PlotNFT wallet id during pool change with a redirected remote resource and drive the sequence import -> parse -> preview -> submit so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/Pool.tsx` / `Pool`
- Entrypoint: payout instruction update
- Attacker controls: stale PlotNFT wallet id during pool change; with a redirected remote resource
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
