# Q3224: pool-plotnft via PlotNFTGetPoolLoginLinkDialog 3224

## Question
Can an unprivileged attacker entering through the payout instruction update in `PlotNFTGetPoolLoginLinkDialog` (packages/gui/src/components/plotNFT/PlotNFTGetPoolLoginLinkDialog.tsx) control fee/reward amount near precision boundary with conflicting localStorage preferences and drive the sequence validate input -> normalize payload -> call RPC so the GUI would route pool login links through unsafe external URL handling, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTGetPoolLoginLinkDialog.tsx` / `PlotNFTGetPoolLoginLinkDialog`
- Entrypoint: payout instruction update
- Attacker controls: fee/reward amount near precision boundary; with conflicting localStorage preferences
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
