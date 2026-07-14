# Q2520: rpc-state via readData 2520

## Question
Can an unprivileged attacker entering through the service command response correlation in `readData` (packages/gui/src/electron/utils/yamlUtils.ts) control RPC error payload shaped like success after a profile switch and drive the sequence import -> parse -> preview -> submit so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/yamlUtils.ts` / `readData`
- Entrypoint: service command response correlation
- Attacker controls: RPC error payload shaped like success; after a profile switch
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
