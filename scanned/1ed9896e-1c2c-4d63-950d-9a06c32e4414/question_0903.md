# Q903: rpc-state via useIntersectionObserver 903

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `useIntersectionObserver` (packages/gui/src/hooks/useIntersectionObserver.ts) control subscription event for a different wallet/fingerprint during a pending modal confirmation and drive the sequence connect -> approve -> switch context -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/hooks/useIntersectionObserver.ts` / `useIntersectionObserver`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; during a pending modal confirmation
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
