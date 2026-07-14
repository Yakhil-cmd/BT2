# Q906: rpc-state via useSelectDirectory 906

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `useSelectDirectory` (packages/gui/src/hooks/useSelectDirectory.tsx) control large numeric fields near JS precision limits with a cached permission entry and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/hooks/useSelectDirectory.tsx` / `useSelectDirectory`
- Entrypoint: daemon RPC response handling
- Attacker controls: large numeric fields near JS precision limits; with a cached permission entry
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
