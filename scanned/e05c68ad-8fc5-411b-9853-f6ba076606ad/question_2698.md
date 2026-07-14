# Q2698: pool-plotnft via PoolAbsorbRewards 2698

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `PoolAbsorbRewards` (packages/gui/src/components/pool/PoolAbsorbRewards.tsx) control payout address with network or Unicode ambiguity after canceling and reopening the dialog and drive the sequence select -> edit backing object -> submit so the GUI would route pool login links through unsafe external URL handling, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolAbsorbRewards.tsx` / `PoolAbsorbRewards`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: payout address with network or Unicode ambiguity; after canceling and reopening the dialog
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
