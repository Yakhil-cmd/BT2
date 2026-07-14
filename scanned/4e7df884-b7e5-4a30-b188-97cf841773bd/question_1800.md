# Q1800: wallet-send via mojoToChia 1800

## Question
Can an unprivileged attacker entering through the CAT send form submission in `mojoToChia` (packages/core/src/utils/mojoToChia.ts) control clawback timelock fields combined with normal send fields with hidden Unicode characters and drive the sequence load persisted state -> render approval -> execute command so the GUI would round or normalize amount/fee differently between display and RPC payload, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/core/src/utils/mojoToChia.ts` / `mojoToChia`
- Entrypoint: CAT send form submission
- Attacker controls: clawback timelock fields combined with normal send fields; with hidden Unicode characters
- Exploit idea: round or normalize amount/fee differently between display and RPC payload
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
