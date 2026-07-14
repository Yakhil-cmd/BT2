# Q3669: wallet-send via mojoToChiaLocaleString 3669

## Question
Can an unprivileged attacker entering through the fee and amount conversion path in `mojoToChiaLocaleString` (packages/core/src/utils/mojoToChiaLocaleString.ts) control clawback timelock fields combined with normal send fields with a redirected remote resource and drive the sequence select -> edit backing object -> submit so the GUI would accept an address that displays as one target but serializes as another, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/core/src/utils/mojoToChiaLocaleString.ts` / `mojoToChiaLocaleString`
- Entrypoint: fee and amount conversion path
- Attacker controls: clawback timelock fields combined with normal send fields; with a redirected remote resource
- Exploit idea: accept an address that displays as one target but serializes as another
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
