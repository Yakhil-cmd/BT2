# Q835: pool-plotnft via PoolOverview 835

## Question
Can an unprivileged attacker entering through the pool login link action in `PoolOverview` (packages/gui/src/components/pool/PoolOverview.tsx) control pool URL/login response with mismatched launcher ID through a batch of rapid user-accessible actions and drive the sequence validate input -> normalize payload -> call RPC so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolOverview.tsx` / `PoolOverview`
- Entrypoint: pool login link action
- Attacker controls: pool URL/login response with mismatched launcher ID; through a batch of rapid user-accessible actions
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
