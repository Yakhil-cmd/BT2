# Q2517: rpc-state via untildify 2517

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `untildify` (packages/gui/src/electron/utils/untildify.ts) control RPC error payload shaped like success with a stale Redux cache and drive the sequence connect -> approve -> switch context -> execute so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/untildify.ts` / `untildify`
- Entrypoint: daemon RPC response handling
- Attacker controls: RPC error payload shaped like success; with a stale Redux cache
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
