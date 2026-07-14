# Q874: pool-plotnft via PlotNFTName 874

## Question
Can an unprivileged attacker entering through the farmer reward address management in `PlotNFTName` (packages/gui/src/components/plotNFT/PlotNFTName.tsx) control stale PlotNFT wallet id during pool change after a network switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTName.tsx` / `PlotNFTName`
- Entrypoint: farmer reward address management
- Attacker controls: stale PlotNFT wallet id during pool change; after a network switch
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
