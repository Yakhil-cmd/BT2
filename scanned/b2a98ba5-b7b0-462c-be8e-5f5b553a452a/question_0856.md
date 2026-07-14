# Q856: rpc-state via useShowDebugInformation 856

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `useShowDebugInformation` (packages/core/src/hooks/useShowDebugInformation.ts) control subscription event for a different wallet/fingerprint with a cached permission entry and drive the sequence load persisted state -> render approval -> execute command so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useShowDebugInformation.ts` / `useShowDebugInformation`
- Entrypoint: daemon RPC response handling
- Attacker controls: subscription event for a different wallet/fingerprint; with a cached permission entry
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
