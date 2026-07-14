# Q836: rpc-state via SignVerifyDialog 836

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `SignVerifyDialog` (packages/gui/src/components/signVerify/SignVerifyDialog.tsx) control large numeric fields near JS precision limits with a duplicate identifier and drive the sequence preview -> mutate controlled state -> confirm so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/components/signVerify/SignVerifyDialog.tsx` / `SignVerifyDialog`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; with a duplicate identifier
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
