# Q868: wallet-send via validAddress 868

## Question
Can an unprivileged attacker entering through the CAT send form submission in `validAddress` (packages/core/src/utils/validAddress.ts) control amount and fee strings near precision boundaries with a delayed metadata fetch and drive the sequence load persisted state -> render approval -> execute command so the GUI would accept an address that displays as one target but serializes as another, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/core/src/utils/validAddress.ts` / `validAddress`
- Entrypoint: CAT send form submission
- Attacker controls: amount and fee strings near precision boundaries; with a delayed metadata fetch
- Exploit idea: accept an address that displays as one target but serializes as another
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
