# Q3482: pool-plotnft via details 3482

## Question
Can an unprivileged attacker entering through the farmer reward address management in `details` (packages/gui/src/hooks/usePlotNFTDetails.ts) control stale PlotNFT wallet id during pool change with precision-boundary values and drive the sequence select -> edit backing object -> submit so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTDetails.ts` / `details`
- Entrypoint: farmer reward address management
- Attacker controls: stale PlotNFT wallet id during pool change; with precision-boundary values
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
