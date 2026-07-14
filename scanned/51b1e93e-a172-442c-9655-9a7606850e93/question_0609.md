# Q609: pool-plotnft via PlotNFTPayoutInstructionsDialog 609

## Question
Can an unprivileged attacker entering through the farmer reward address management in `PlotNFTPayoutInstructionsDialog` (packages/gui/src/components/plotNFT/PlotNFTPayoutInstructionsDialog.tsx) control fee/reward amount near precision boundary with a redirected remote resource and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTPayoutInstructionsDialog.tsx` / `PlotNFTPayoutInstructionsDialog`
- Entrypoint: farmer reward address management
- Attacker controls: fee/reward amount near precision boundary; with a redirected remote resource
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
