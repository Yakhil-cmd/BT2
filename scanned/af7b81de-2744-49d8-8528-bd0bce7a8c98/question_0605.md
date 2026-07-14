# Q605: pool-plotnft via normalizePoolState 605

## Question
Can an unprivileged attacker entering through the farmer reward address management in `normalizePoolState` (packages/core/src/utils/normalizePoolState.ts) control external pool metadata changing between preview and submit during a pending modal confirmation and drive the sequence select -> edit backing object -> submit so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/core/src/utils/normalizePoolState.ts` / `normalizePoolState`
- Entrypoint: farmer reward address management
- Attacker controls: external pool metadata changing between preview and submit; during a pending modal confirmation
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
