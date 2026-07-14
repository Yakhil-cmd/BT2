# Q1484: pool-plotnft via PlotNFT 1484

## Question
Can an unprivileged attacker entering through the payout instruction update in `PlotNFT` (packages/api/src/@types/PlotNFT.ts) control payout address with network or Unicode ambiguity with hidden Unicode characters and drive the sequence import -> parse -> preview -> submit so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/PlotNFT.ts` / `PlotNFT`
- Entrypoint: payout instruction update
- Attacker controls: payout address with network or Unicode ambiguity; with hidden Unicode characters
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
