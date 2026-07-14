# Q1291: wallet-send via willClawbackBeEnabled 1291

## Question
Can an unprivileged attacker entering through the CAT send form submission in `willClawbackBeEnabled` (packages/wallets/src/components/WalletSend.tsx) control amount and fee strings near precision boundaries during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would reuse stale balance/sync state to authorize a spend that should be blocked, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/wallets/src/components/WalletSend.tsx` / `willClawbackBeEnabled`
- Entrypoint: CAT send form submission
- Attacker controls: amount and fee strings near precision boundaries; during a pending modal confirmation
- Exploit idea: reuse stale balance/sync state to authorize a spend that should be blocked
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
