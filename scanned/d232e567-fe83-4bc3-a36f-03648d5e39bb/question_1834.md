# Q1834: pool-plotnft via if 1834

## Question
Can an unprivileged attacker entering through the farmer reward address management in `if` (packages/gui/src/hooks/useFarmerStatus.ts) control fee/reward amount near precision boundary with a cached permission entry and drive the sequence fetch -> cache -> refresh -> submit so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/useFarmerStatus.ts` / `if`
- Entrypoint: farmer reward address management
- Attacker controls: fee/reward amount near precision boundary; with a cached permission entry
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
