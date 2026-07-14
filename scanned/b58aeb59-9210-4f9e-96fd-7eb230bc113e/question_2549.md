# Q2549: pool-plotnft via if 2549

## Question
Can an unprivileged attacker entering through the pool login link action in `if` (packages/gui/src/hooks/usePlotNFTName.ts) control payout address with network or Unicode ambiguity with a cached permission entry and drive the sequence load persisted state -> render approval -> execute command so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTName.ts` / `if`
- Entrypoint: pool login link action
- Attacker controls: payout address with network or Unicode ambiguity; with a cached permission entry
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
