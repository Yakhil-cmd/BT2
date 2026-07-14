# Q1811: pool-plotnft via PlotNFTSelectBase 1811

## Question
Can an unprivileged attacker entering through the farmer reward address management in `PlotNFTSelectBase` (packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx) control pool URL/login response with mismatched launcher ID with reordered RPC events and drive the sequence validate input -> normalize payload -> call RPC so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx` / `PlotNFTSelectBase`
- Entrypoint: farmer reward address management
- Attacker controls: pool URL/login response with mismatched launcher ID; with reordered RPC events
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
