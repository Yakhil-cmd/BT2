# Q3160: wallet-send via CreateWalletSendTransactionResultDialog 3160

## Question
Can an unprivileged attacker entering through the receive-address copy/new-address flow in `CreateWalletSendTransactionResultDialog` (packages/wallets/src/components/WalletSendTransactionResultDialog.tsx) control rapid wallet/profile switching during submit with reordered RPC events and drive the sequence connect -> approve -> switch context -> execute so the GUI would make the GUI submit a spend for a different wallet or asset than the confirmation showed, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/wallets/src/components/WalletSendTransactionResultDialog.tsx` / `CreateWalletSendTransactionResultDialog`
- Entrypoint: receive-address copy/new-address flow
- Attacker controls: rapid wallet/profile switching during submit; with reordered RPC events
- Exploit idea: make the GUI submit a spend for a different wallet or asset than the confirmation showed
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
