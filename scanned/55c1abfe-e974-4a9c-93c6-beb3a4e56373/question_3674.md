# Q3674: pool-plotnft via handleAddPlot 3674

## Question
Can an unprivileged attacker entering through the farmer reward address management in `handleAddPlot` (packages/gui/src/components/plotNFT/PlotNFTCard.tsx) control stale PlotNFT wallet id during pool change with a stale Redux cache and drive the sequence open notification -> resolve details -> execute so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTCard.tsx` / `handleAddPlot`
- Entrypoint: farmer reward address management
- Attacker controls: stale PlotNFT wallet id during pool change; with a stale Redux cache
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
