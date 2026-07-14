# Q3678: pool-plotnft via if 3678

## Question
Can an unprivileged attacker entering through the farmer reward address management in `if` (packages/gui/src/components/plotNFT/PlotNFTUnconfirmedCard.tsx) control stale PlotNFT wallet id during pool change through a batch of rapid user-accessible actions and drive the sequence select -> edit backing object -> submit so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTUnconfirmedCard.tsx` / `if`
- Entrypoint: farmer reward address management
- Attacker controls: stale PlotNFT wallet id during pool change; through a batch of rapid user-accessible actions
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
