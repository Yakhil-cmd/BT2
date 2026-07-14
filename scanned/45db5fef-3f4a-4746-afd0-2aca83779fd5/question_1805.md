# Q1805: pool-plotnft via handleSubmit 1805

## Question
Can an unprivileged attacker entering through the farmer reward address management in `handleSubmit` (packages/gui/src/components/plotNFT/PlotNFTAdd.tsx) control fee/reward amount near precision boundary with a duplicate identifier and drive the sequence preview -> mutate controlled state -> confirm so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTAdd.tsx` / `handleSubmit`
- Entrypoint: farmer reward address management
- Attacker controls: fee/reward amount near precision boundary; with a duplicate identifier
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
