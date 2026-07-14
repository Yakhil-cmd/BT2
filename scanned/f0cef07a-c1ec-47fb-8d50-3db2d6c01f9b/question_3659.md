# Q3659: rpc-state via showError 3659

## Question
Can an unprivileged attacker entering through the service command response correlation in `showError` (packages/core/src/hooks/useShowError.tsx) control subscription event for a different wallet/fingerprint with reordered RPC events and drive the sequence preview -> mutate controlled state -> confirm so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useShowError.tsx` / `showError`
- Entrypoint: service command response correlation
- Attacker controls: subscription event for a different wallet/fingerprint; with reordered RPC events
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
