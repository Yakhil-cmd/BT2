# Q463: wallet-send via normalizeHex 463

## Question
Can an unprivileged attacker entering through the wallet RPC send command in `normalizeHex` (packages/gui/src/electron/utils/normalizeHex.ts) control amount and fee strings near precision boundaries with case-normalized identifiers and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would reuse stale balance/sync state to authorize a spend that should be blocked, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/normalizeHex.ts` / `normalizeHex`
- Entrypoint: wallet RPC send command
- Attacker controls: amount and fee strings near precision boundaries; with case-normalized identifiers
- Exploit idea: reuse stale balance/sync state to authorize a spend that should be blocked
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
