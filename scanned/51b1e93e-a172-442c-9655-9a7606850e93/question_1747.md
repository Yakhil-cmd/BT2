# Q1747: wallet-send via toBech32m 1747

## Question
Can an unprivileged attacker entering through the CAT send form submission in `toBech32m` (packages/api/src/utils/toBech32m.ts) control amount and fee strings near precision boundaries after a profile switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would reuse stale balance/sync state to authorize a spend that should be blocked, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/api/src/utils/toBech32m.ts` / `toBech32m`
- Entrypoint: CAT send form submission
- Attacker controls: amount and fee strings near precision boundaries; after a profile switch
- Exploit idea: reuse stale balance/sync state to authorize a spend that should be blocked
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
