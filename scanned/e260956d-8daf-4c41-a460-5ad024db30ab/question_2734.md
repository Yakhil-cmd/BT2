# Q2734: wallet-send via mojoToChia 2734

## Question
Can an unprivileged attacker entering through the wallet send form submission in `mojoToChia` (packages/core/src/utils/mojoToChia.ts) control amount and fee strings near precision boundaries after a failed RPC response and drive the sequence preview -> mutate controlled state -> confirm so the GUI would drop or alter clawback restrictions while still showing a clawback-protected send, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/core/src/utils/mojoToChia.ts` / `mojoToChia`
- Entrypoint: wallet send form submission
- Attacker controls: amount and fee strings near precision boundaries; after a failed RPC response
- Exploit idea: drop or alter clawback restrictions while still showing a clawback-protected send
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
