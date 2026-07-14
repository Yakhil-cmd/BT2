# Q884: rpc-state via SettingsCustodyClawbackOutgoing 884

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `SettingsCustodyClawbackOutgoing` (packages/gui/src/components/settings/SettingsCustodyClawbackOutgoing.tsx) control response object with duplicate camelCase/snake_case keys with hidden Unicode characters and drive the sequence load persisted state -> render approval -> execute command so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/components/settings/SettingsCustodyClawbackOutgoing.tsx` / `SettingsCustodyClawbackOutgoing`
- Entrypoint: daemon RPC response handling
- Attacker controls: response object with duplicate camelCase/snake_case keys; with hidden Unicode characters
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
