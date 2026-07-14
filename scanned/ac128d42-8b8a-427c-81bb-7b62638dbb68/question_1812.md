# Q1812: pool-plotnft via handleClick 1812

## Question
Can an unprivileged attacker entering through the payout instruction update in `handleClick` (packages/gui/src/components/plotNFT/select/PlotNFTSelectFaucet.tsx) control external pool metadata changing between preview and submit with a duplicate identifier and drive the sequence preview -> mutate controlled state -> confirm so the GUI would route pool login links through unsafe external URL handling, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/select/PlotNFTSelectFaucet.tsx` / `handleClick`
- Entrypoint: payout instruction update
- Attacker controls: external pool metadata changing between preview and submit; with a duplicate identifier
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
