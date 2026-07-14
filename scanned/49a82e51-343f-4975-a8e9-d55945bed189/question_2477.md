# Q2477: pool-plotnft via handleSubmit 2477

## Question
Can an unprivileged attacker entering through the payout instruction update in `handleSubmit` (packages/gui/src/components/plotNFT/PlotNFTPayoutInstructionsDialog.tsx) control stale PlotNFT wallet id during pool change with hidden Unicode characters and drive the sequence connect -> approve -> switch context -> execute so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTPayoutInstructionsDialog.tsx` / `handleSubmit`
- Entrypoint: payout instruction update
- Attacker controls: stale PlotNFT wallet id during pool change; with hidden Unicode characters
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
