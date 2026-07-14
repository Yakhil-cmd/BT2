# Q3161: wallet-send via CreateWalletSendTransactionResultDialog 3161

## Question
Can an unprivileged attacker entering through the wallet RPC send command in `CreateWalletSendTransactionResultDialog` (packages/wallets/src/components/WalletSendTransactionResultDialog.tsx) control rapid wallet/profile switching during submit with reordered RPC events and drive the sequence connect -> approve -> switch context -> execute so the GUI would round or normalize amount/fee differently between display and RPC payload, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/wallets/src/components/WalletSendTransactionResultDialog.tsx` / `CreateWalletSendTransactionResultDialog`
- Entrypoint: wallet RPC send command
- Attacker controls: rapid wallet/profile switching during submit; with reordered RPC events
- Exploit idea: round or normalize amount/fee differently between display and RPC payload
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
