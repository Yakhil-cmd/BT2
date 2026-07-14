# Q3483: pool-plotnft via usePlotNFTName 3483

## Question
Can an unprivileged attacker entering through the payout instruction update in `usePlotNFTName` (packages/gui/src/hooks/usePlotNFTName.ts) control external pool metadata changing between preview and submit with reordered RPC events and drive the sequence import -> parse -> preview -> submit so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTName.ts` / `usePlotNFTName`
- Entrypoint: payout instruction update
- Attacker controls: external pool metadata changing between preview and submit; with reordered RPC events
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
