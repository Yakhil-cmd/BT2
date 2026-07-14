# Q3673: pool-plotnft via handleSubmit 3673

## Question
Can an unprivileged attacker entering through the payout instruction update in `handleSubmit` (packages/gui/src/components/plotNFT/PlotNFTAdd.tsx) control payout address with network or Unicode ambiguity with a cached permission entry and drive the sequence select -> edit backing object -> submit so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTAdd.tsx` / `handleSubmit`
- Entrypoint: payout instruction update
- Attacker controls: payout address with network or Unicode ambiguity; with a cached permission entry
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
