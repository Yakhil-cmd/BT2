# Q2808: rpc-state via updateRecoveryIds 2808

## Question
Can an unprivileged attacker entering through the service command response correlation in `updateRecoveryIds` (packages/api/src/wallets/DID.ts) control RPC error payload shaped like success with a redirected remote resource and drive the sequence connect -> approve -> switch context -> execute so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/DID.ts` / `updateRecoveryIds`
- Entrypoint: service command response correlation
- Attacker controls: RPC error payload shaped like success; with a redirected remote resource
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
