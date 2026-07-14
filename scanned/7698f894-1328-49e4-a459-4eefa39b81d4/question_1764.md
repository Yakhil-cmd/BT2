# Q1764: pool-plotnft via handleAbsorbRewards 1764

## Question
Can an unprivileged attacker entering through the payout instruction update in `handleAbsorbRewards` (packages/gui/src/components/pool/PoolAbsorbRewards.tsx) control payout address with network or Unicode ambiguity with a duplicate identifier and drive the sequence select -> edit backing object -> submit so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolAbsorbRewards.tsx` / `handleAbsorbRewards`
- Entrypoint: payout instruction update
- Attacker controls: payout address with network or Unicode ambiguity; with a duplicate identifier
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
