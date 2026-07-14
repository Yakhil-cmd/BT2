# Q3638: rpc-state via SignVerifyDialog 3638

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `SignVerifyDialog` (packages/gui/src/components/signVerify/SignVerifyDialog.tsx) control subscription event for a different wallet/fingerprint with a delayed metadata fetch and drive the sequence open notification -> resolve details -> execute so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/components/signVerify/SignVerifyDialog.tsx` / `SignVerifyDialog`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; with a delayed metadata fetch
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
