# Q1763: pool-plotnft via Pool 1763

## Question
Can an unprivileged attacker entering through the pool login link action in `Pool` (packages/gui/src/components/pool/Pool.tsx) control payout address with network or Unicode ambiguity with case-normalized identifiers and drive the sequence download or render content -> trigger linked wallet action so the GUI would route pool login links through unsafe external URL handling, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/Pool.tsx` / `Pool`
- Entrypoint: pool login link action
- Attacker controls: payout address with network or Unicode ambiguity; with case-normalized identifiers
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
