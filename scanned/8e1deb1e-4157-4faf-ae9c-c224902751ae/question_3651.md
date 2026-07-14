# Q3651: rpc-state via if 3651

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `if` (packages/core/src/hooks/useLocale.ts) control subscription event for a different wallet/fingerprint with a cached permission entry and drive the sequence connect -> approve -> switch context -> execute so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useLocale.ts` / `if`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; with a cached permission entry
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
