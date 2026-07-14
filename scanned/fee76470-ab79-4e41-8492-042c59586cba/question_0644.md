# Q644: rpc-state via sanitizeNumber 644

## Question
Can an unprivileged attacker entering through the RTK query cache update in `sanitizeNumber` (packages/gui/src/electron/utils/sanitizeNumber.ts) control subscription event for a different wallet/fingerprint after canceling and reopening the dialog and drive the sequence fetch -> cache -> refresh -> submit so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/sanitizeNumber.ts` / `sanitizeNumber`
- Entrypoint: RTK query cache update
- Attacker controls: subscription event for a different wallet/fingerprint; after canceling and reopening the dialog
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
