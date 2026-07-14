# Q2681: wallet-send via if 2681

## Question
Can an unprivileged attacker entering through the wallet send form submission in `if` (packages/api/src/utils/toBech32m.ts) control destination address with mixed prefix/case or hidden characters with a duplicate identifier and drive the sequence load persisted state -> render approval -> execute command so the GUI would round or normalize amount/fee differently between display and RPC payload, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/api/src/utils/toBech32m.ts` / `if`
- Entrypoint: wallet send form submission
- Attacker controls: destination address with mixed prefix/case or hidden characters; with a duplicate identifier
- Exploit idea: round or normalize amount/fee differently between display and RPC payload
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
