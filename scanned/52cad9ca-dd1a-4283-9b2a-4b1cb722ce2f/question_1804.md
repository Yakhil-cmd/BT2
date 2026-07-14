# Q1804: pool-plotnft via nft 1804

## Question
Can an unprivileged attacker entering through the pool login link action in `nft` (packages/gui/src/components/plotNFT/PlotNFTAbsorbRewards.tsx) control external pool metadata changing between preview and submit with a cached permission entry and drive the sequence import -> parse -> preview -> submit so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTAbsorbRewards.tsx` / `nft`
- Entrypoint: pool login link action
- Attacker controls: external pool metadata changing between preview and submit; with a cached permission entry
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
