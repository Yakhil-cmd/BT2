# Q423: pool-plotnft via PlotNFTGetPoolLoginLinkDialog 423

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `PlotNFTGetPoolLoginLinkDialog` (packages/gui/src/components/plotNFT/PlotNFTGetPoolLoginLinkDialog.tsx) control external pool metadata changing between preview and submit after canceling and reopening the dialog and drive the sequence import -> parse -> preview -> submit so the GUI would route pool login links through unsafe external URL handling, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTGetPoolLoginLinkDialog.tsx` / `PlotNFTGetPoolLoginLinkDialog`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: external pool metadata changing between preview and submit; after canceling and reopening the dialog
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
