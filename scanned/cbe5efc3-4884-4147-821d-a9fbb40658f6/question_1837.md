# Q1837: rpc-state via updateEntry 1837

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `updateEntry` (packages/gui/src/hooks/useIntersectionObserver.ts) control subscription event for a different wallet/fingerprint with precision-boundary values and drive the sequence connect -> approve -> switch context -> execute so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/hooks/useIntersectionObserver.ts` / `updateEntry`
- Entrypoint: daemon RPC response handling
- Attacker controls: subscription event for a different wallet/fingerprint; with precision-boundary values
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
