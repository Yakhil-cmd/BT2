# Q3633: pool-plotnft via PoolHeader 3633

## Question
Can an unprivileged attacker entering through the farmer reward address management in `PoolHeader` (packages/gui/src/components/pool/PoolHeader.tsx) control pool URL/login response with mismatched launcher ID with case-normalized identifiers and drive the sequence download or render content -> trigger linked wallet action so the GUI would route pool login links through unsafe external URL handling, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolHeader.tsx` / `PoolHeader`
- Entrypoint: farmer reward address management
- Attacker controls: pool URL/login response with mismatched launcher ID; with case-normalized identifiers
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
