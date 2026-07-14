# Q872: pool-plotnft via StyledSyncingFooter 872

## Question
Can an unprivileged attacker entering through the payout instruction update in `StyledSyncingFooter` (packages/gui/src/components/plotNFT/PlotNFTCard.tsx) control external pool metadata changing between preview and submit after a network switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTCard.tsx` / `StyledSyncingFooter`
- Entrypoint: payout instruction update
- Attacker controls: external pool metadata changing between preview and submit; after a network switch
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
