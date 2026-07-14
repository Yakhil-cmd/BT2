# Q2266: wallet-send via farm 2266

## Question
Can an unprivileged attacker entering through the receive-address copy/new-address flow in `farm` (packages/wallets/src/components/cat/WalletCATSend.tsx) control clawback timelock fields combined with normal send fields after a network switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would round or normalize amount/fee differently between display and RPC payload, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/wallets/src/components/cat/WalletCATSend.tsx` / `farm`
- Entrypoint: receive-address copy/new-address flow
- Attacker controls: clawback timelock fields combined with normal send fields; after a network switch
- Exploit idea: round or normalize amount/fee differently between display and RPC payload
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
