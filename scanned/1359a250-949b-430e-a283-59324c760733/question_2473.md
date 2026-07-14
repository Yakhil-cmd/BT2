# Q2473: pool-plotnft via normalizePoolState 2473

## Question
Can an unprivileged attacker entering through the payout instruction update in `normalizePoolState` (packages/core/src/utils/normalizePoolState.ts) control stale PlotNFT wallet id during pool change after a failed RPC response and drive the sequence load persisted state -> render approval -> execute command so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/core/src/utils/normalizePoolState.ts` / `normalizePoolState`
- Entrypoint: payout instruction update
- Attacker controls: stale PlotNFT wallet id during pool change; after a failed RPC response
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
