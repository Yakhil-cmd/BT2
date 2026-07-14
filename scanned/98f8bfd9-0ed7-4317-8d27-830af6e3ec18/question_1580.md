# Q1580: wallet-send via toBech32m 1580

## Question
Can an unprivileged attacker entering through the receive-address copy/new-address flow in `toBech32m` (packages/gui/src/electron/utils/toBech32m.ts) control destination address with mixed prefix/case or hidden characters after canceling and reopening the dialog and drive the sequence preview -> mutate controlled state -> confirm so the GUI would reuse stale balance/sync state to authorize a spend that should be blocked, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/toBech32m.ts` / `toBech32m`
- Entrypoint: receive-address copy/new-address flow
- Attacker controls: destination address with mixed prefix/case or hidden characters; after canceling and reopening the dialog
- Exploit idea: reuse stale balance/sync state to authorize a spend that should be blocked
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
