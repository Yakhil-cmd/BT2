# Q3503: wallet-send via if 3503

## Question
Can an unprivileged attacker entering through the wallet send form submission in `if` (packages/gui/src/util/parseFee.ts) control clawback timelock fields combined with normal send fields with a cached permission entry and drive the sequence import -> parse -> preview -> submit so the GUI would drop or alter clawback restrictions while still showing a clawback-protected send, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/util/parseFee.ts` / `if`
- Entrypoint: wallet send form submission
- Attacker controls: clawback timelock fields combined with normal send fields; with a cached permission entry
- Exploit idea: drop or alter clawback restrictions while still showing a clawback-protected send
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
