# Q878: pool-plotnft via PlotNFTSelectFaucet 878

## Question
Can an unprivileged attacker entering through the pool login link action in `PlotNFTSelectFaucet` (packages/gui/src/components/plotNFT/select/PlotNFTSelectFaucet.tsx) control payout address with network or Unicode ambiguity after a profile switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/select/PlotNFTSelectFaucet.tsx` / `PlotNFTSelectFaucet`
- Entrypoint: pool login link action
- Attacker controls: payout address with network or Unicode ambiguity; after a profile switch
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
