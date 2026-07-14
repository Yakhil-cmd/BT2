# Q3097: rpc-state via if 3097

## Question
Can an unprivileged attacker entering through the service command response correlation in `if` (packages/gui/src/electron/api/isMainnet.ts) control large numeric fields near JS precision limits during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/api/isMainnet.ts` / `if`
- Entrypoint: service command response correlation
- Attacker controls: large numeric fields near JS precision limits; during a pending modal confirmation
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
