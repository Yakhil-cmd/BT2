# Q1620: wallet-send via wallet 1620

## Question
Can an unprivileged attacker entering through the fee and amount conversion path in `wallet` (packages/gui/src/hooks/useStandardWallet.ts) control destination address with mixed prefix/case or hidden characters with a redirected remote resource and drive the sequence preview -> mutate controlled state -> confirm so the GUI would round or normalize amount/fee differently between display and RPC payload, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/hooks/useStandardWallet.ts` / `wallet`
- Entrypoint: fee and amount conversion path
- Attacker controls: destination address with mixed prefix/case or hidden characters; with a redirected remote resource
- Exploit idea: round or normalize amount/fee differently between display and RPC payload
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
