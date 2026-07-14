# Q3411: pool-plotnft via handleDialogClose 3411

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `handleDialogClose` (packages/gui/src/components/plotNFT/PlotNFTPayoutInstructionsDialog.tsx) control fee/reward amount near precision boundary after a failed RPC response and drive the sequence download or render content -> trigger linked wallet action so the GUI would route pool login links through unsafe external URL handling, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTPayoutInstructionsDialog.tsx` / `handleDialogClose`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: fee/reward amount near precision boundary; after a failed RPC response
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
