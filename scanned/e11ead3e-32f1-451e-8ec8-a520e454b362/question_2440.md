# Q2440: wallet-send via normalizeHex 2440

## Question
Can an unprivileged attacker entering through the fee and amount conversion path in `normalizeHex` (packages/api/src/utils/normalizeHex.ts) control destination address with mixed prefix/case or hidden characters during a pending modal confirmation and drive the sequence download or render content -> trigger linked wallet action so the GUI would make the GUI submit a spend for a different wallet or asset than the confirmation showed, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/api/src/utils/normalizeHex.ts` / `normalizeHex`
- Entrypoint: fee and amount conversion path
- Attacker controls: destination address with mixed prefix/case or hidden characters; during a pending modal confirmation
- Exploit idea: make the GUI submit a spend for a different wallet or asset than the confirmation showed
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
