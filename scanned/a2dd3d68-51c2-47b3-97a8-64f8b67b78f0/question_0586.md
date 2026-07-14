# Q586: rpc-state via SignMessageResultDialog 586

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `SignMessageResultDialog` (packages/gui/src/components/signVerify/SignMessageResultDialog.tsx) control subscription event for a different wallet/fingerprint with precision-boundary values and drive the sequence load persisted state -> render approval -> execute command so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/components/signVerify/SignMessageResultDialog.tsx` / `SignMessageResultDialog`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; with precision-boundary values
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
