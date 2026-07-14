# Q3386: rpc-state via handleSignByAddress 3386

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `handleSignByAddress` (packages/gui/src/components/signVerify/SignMessage.tsx) control RPC error payload shaped like success with case-normalized identifiers and drive the sequence download or render content -> trigger linked wallet action so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/components/signVerify/SignMessage.tsx` / `handleSignByAddress`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; with case-normalized identifiers
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
