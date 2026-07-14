# Q3601: rpc-state via startService 3601

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `startService` (packages/api/src/services/Daemon.ts) control RPC error payload shaped like success with conflicting localStorage preferences and drive the sequence load persisted state -> render approval -> execute command so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/services/Daemon.ts` / `startService`
- Entrypoint: daemon RPC response handling
- Attacker controls: RPC error payload shaped like success; with conflicting localStorage preferences
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
