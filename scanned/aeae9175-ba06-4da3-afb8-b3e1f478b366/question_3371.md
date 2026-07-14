# Q3371: rpc-state via addMissingFiles 3371

## Question
Can an unprivileged attacker entering through the service command response correlation in `addMissingFiles` (packages/api/src/services/DataLayer.ts) control subscription event for a different wallet/fingerprint with hidden Unicode characters and drive the sequence select -> edit backing object -> submit so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/services/DataLayer.ts` / `addMissingFiles`
- Entrypoint: service command response correlation
- Attacker controls: subscription event for a different wallet/fingerprint; with hidden Unicode characters
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
