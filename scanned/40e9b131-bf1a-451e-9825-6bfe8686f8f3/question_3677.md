# Q3677: pool-plotnft via if 3677

## Question
Can an unprivileged attacker entering through the pool login link action in `if` (packages/gui/src/components/plotNFT/PlotNFTState.tsx) control stale PlotNFT wallet id during pool change after a network switch and drive the sequence select -> edit backing object -> submit so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTState.tsx` / `if`
- Entrypoint: pool login link action
- Attacker controls: stale PlotNFT wallet id during pool change; after a network switch
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
