# Q3265: wallet-send via normalizeHex 3265

## Question
Can an unprivileged attacker entering through the CAT send form submission in `normalizeHex` (packages/gui/src/electron/utils/normalizeHex.ts) control destination address with mixed prefix/case or hidden characters with precision-boundary values and drive the sequence fetch -> cache -> refresh -> submit so the GUI would reuse stale balance/sync state to authorize a spend that should be blocked, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/normalizeHex.ts` / `normalizeHex`
- Entrypoint: CAT send form submission
- Attacker controls: destination address with mixed prefix/case or hidden characters; with precision-boundary values
- Exploit idea: reuse stale balance/sync state to authorize a spend that should be blocked
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
