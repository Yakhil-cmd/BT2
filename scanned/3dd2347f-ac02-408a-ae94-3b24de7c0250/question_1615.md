# Q1615: pool-plotnft via computedName 1615

## Question
Can an unprivileged attacker entering through the farmer reward address management in `computedName` (packages/gui/src/hooks/usePlotNFTName.ts) control pool URL/login response with mismatched launcher ID with conflicting localStorage preferences and drive the sequence validate input -> normalize payload -> call RPC so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTName.ts` / `computedName`
- Entrypoint: farmer reward address management
- Attacker controls: pool URL/login response with mismatched launcher ID; with conflicting localStorage preferences
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
