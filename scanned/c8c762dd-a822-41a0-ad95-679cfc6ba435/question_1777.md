# Q1777: rpc-state via if 1777

## Question
Can an unprivileged attacker entering through the service command response correlation in `if` (packages/core/src/hooks/useCurrencyCode.ts) control large numeric fields near JS precision limits after canceling and reopening the dialog and drive the sequence load persisted state -> render approval -> execute command so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useCurrencyCode.ts` / `if`
- Entrypoint: service command response correlation
- Attacker controls: large numeric fields near JS precision limits; after canceling and reopening the dialog
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
