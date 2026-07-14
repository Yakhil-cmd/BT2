# Q3200: wallet-send via handleSubmit 3200

## Question
Can an unprivileged attacker entering through the fee and amount conversion path in `handleSubmit` (packages/wallets/src/components/cat/WalletCATSend.tsx) control stale walletId from route or dropdown state with precision-boundary values and drive the sequence load persisted state -> render approval -> execute command so the GUI would accept an address that displays as one target but serializes as another, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/wallets/src/components/cat/WalletCATSend.tsx` / `handleSubmit`
- Entrypoint: fee and amount conversion path
- Attacker controls: stale walletId from route or dropdown state; with precision-boundary values
- Exploit idea: accept an address that displays as one target but serializes as another
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
