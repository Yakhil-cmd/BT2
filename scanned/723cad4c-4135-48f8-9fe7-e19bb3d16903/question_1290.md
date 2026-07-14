# Q1290: wallet-send via willClawbackBeEnabled 1290

## Question
Can an unprivileged attacker entering through the wallet send form submission in `willClawbackBeEnabled` (packages/wallets/src/components/WalletSend.tsx) control destination address with mixed prefix/case or hidden characters during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would drop or alter clawback restrictions while still showing a clawback-protected send, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/wallets/src/components/WalletSend.tsx` / `willClawbackBeEnabled`
- Entrypoint: wallet send form submission
- Attacker controls: destination address with mixed prefix/case or hidden characters; during a pending modal confirmation
- Exploit idea: drop or alter clawback restrictions while still showing a clawback-protected send
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
