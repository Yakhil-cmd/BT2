# Q141: pool-plotnft via PlotNFTExternal 141

## Question
Can an unprivileged attacker entering through the payout instruction update in `PlotNFTExternal` (packages/api/src/@types/PlotNFTExternal.ts) control payout address with network or Unicode ambiguity with a duplicate identifier and drive the sequence open notification -> resolve details -> execute so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/PlotNFTExternal.ts` / `PlotNFTExternal`
- Entrypoint: payout instruction update
- Attacker controls: payout address with network or Unicode ambiguity; with a duplicate identifier
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
