# Q3295: pool-plotnft via details 3295

## Question
Can an unprivileged attacker entering through the pool join/change flow in `details` (packages/gui/src/hooks/usePlotNFTExternalDetails.ts) control pool URL/login response with mismatched launcher ID with a redirected remote resource and drive the sequence preview -> mutate controlled state -> confirm so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTExternalDetails.ts` / `details`
- Entrypoint: pool join/change flow
- Attacker controls: pool URL/login response with mismatched launcher ID; with a redirected remote resource
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
