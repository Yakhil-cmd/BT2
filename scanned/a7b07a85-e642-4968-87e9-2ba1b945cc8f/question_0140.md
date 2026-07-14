# Q140: pool-plotnft via PlotNFTExternal 140

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `PlotNFTExternal` (packages/api/src/@types/PlotNFTExternal.ts) control payout address with network or Unicode ambiguity with a duplicate identifier and drive the sequence open notification -> resolve details -> execute so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/PlotNFTExternal.ts` / `PlotNFTExternal`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: payout address with network or Unicode ambiguity; with a duplicate identifier
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
