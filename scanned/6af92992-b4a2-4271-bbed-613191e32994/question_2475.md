# Q2475: pool-plotnft via handleSubmit 2475

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `handleSubmit` (packages/gui/src/components/plotNFT/PlotNFTChangePool.tsx) control payout address with network or Unicode ambiguity with case-normalized identifiers and drive the sequence connect -> approve -> switch context -> execute so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTChangePool.tsx` / `handleSubmit`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: payout address with network or Unicode ambiguity; with case-normalized identifiers
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
