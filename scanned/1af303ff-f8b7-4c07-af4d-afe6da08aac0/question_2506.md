# Q2506: rpc-state via isPlainObject 2506

## Question
Can an unprivileged attacker entering through the service command response correlation in `isPlainObject` (packages/gui/src/electron/utils/isPlainObject.ts) control subscription event for a different wallet/fingerprint during a pending modal confirmation and drive the sequence open notification -> resolve details -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/isPlainObject.ts` / `isPlainObject`
- Entrypoint: service command response correlation
- Attacker controls: subscription event for a different wallet/fingerprint; during a pending modal confirmation
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
