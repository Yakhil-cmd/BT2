# Q1356: pool-plotnft via handleClose 1356

## Question
Can an unprivileged attacker entering through the farmer reward address management in `handleClose` (packages/gui/src/components/plotNFT/PlotNFTGetPoolLoginLinkDialog.tsx) control stale PlotNFT wallet id during pool change with a stale Redux cache and drive the sequence open notification -> resolve details -> execute so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTGetPoolLoginLinkDialog.tsx` / `handleClose`
- Entrypoint: farmer reward address management
- Attacker controls: stale PlotNFT wallet id during pool change; with a stale Redux cache
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
