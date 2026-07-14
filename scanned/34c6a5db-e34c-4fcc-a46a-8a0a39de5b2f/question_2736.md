# Q2736: wallet-send via validAddress 2736

## Question
Can an unprivileged attacker entering through the wallet RPC send command in `validAddress` (packages/core/src/utils/validAddress.ts) control stale walletId from route or dropdown state with a cached permission entry and drive the sequence connect -> approve -> switch context -> execute so the GUI would round or normalize amount/fee differently between display and RPC payload, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/core/src/utils/validAddress.ts` / `validAddress`
- Entrypoint: wallet RPC send command
- Attacker controls: stale walletId from route or dropdown state; with a cached permission entry
- Exploit idea: round or normalize amount/fee differently between display and RPC payload
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
