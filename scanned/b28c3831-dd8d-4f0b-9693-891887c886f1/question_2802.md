# Q2802: rpc-state via createOfferNotificationPayload 2802

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `createOfferNotificationPayload` (packages/gui/src/components/notification/utils.ts) control subscription event for a different wallet/fingerprint with a cached permission entry and drive the sequence open notification -> resolve details -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/components/notification/utils.ts` / `createOfferNotificationPayload`
- Entrypoint: daemon RPC response handling
- Attacker controls: subscription event for a different wallet/fingerprint; with a cached permission entry
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
