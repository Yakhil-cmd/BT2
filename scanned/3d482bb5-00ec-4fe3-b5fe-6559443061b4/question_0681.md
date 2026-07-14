# Q681: pool-plotnft via getUniqueName 681

## Question
Can an unprivileged attacker entering through the pool join/change flow in `getUniqueName` (packages/gui/src/hooks/usePlotNFTName.ts) control external pool metadata changing between preview and submit with a delayed metadata fetch and drive the sequence open notification -> resolve details -> execute so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTName.ts` / `getUniqueName`
- Entrypoint: pool join/change flow
- Attacker controls: external pool metadata changing between preview and submit; with a delayed metadata fetch
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
